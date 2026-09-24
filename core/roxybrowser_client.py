# -*- coding: utf-8 -*-
"""Client API cục bộ RoxyBrowser."""
from __future__ import annotations

import json
import logging
import random
import threading
import time
from dataclasses import dataclass
from urllib.parse import unquote, urljoin, urlparse

import requests

from config import roxybrowser as _cfg

logger = logging.getLogger(__name__)

# /browser/create của Roxy khi nhiều worker đến cùng lúc có thể trả về "đang tạo".
# Chia sẻ khe thời gian tạo cho mọi instance client, đảm bảo thời điểm bắt đầu request trong process lệch ít nhất khoảng cấu hình.
_CREATE_SLOT_LOCK = threading.Lock()
_NEXT_CREATE_SLOT = 0.0
# Tuần tự hóa từ tạo Profile đến khi nhận địa chỉ debug, tránh cạnh tranh kernel/cổng Roxy.
_ROXY_WINDOW_CREATE_LOCK = threading.Lock()


def _wait_for_create_slot() -> None:
    global _NEXT_CREATE_SLOT

    interval = max(0.0, float(getattr(_cfg, "ROXY_CREATE_INTERVAL", 1.5) or 0.0))
    if interval <= 0:
        return

    with _CREATE_SLOT_LOCK:
        now = time.monotonic()
        wait_for = max(0.0, _NEXT_CREATE_SLOT - now)
        _NEXT_CREATE_SLOT = max(now, _NEXT_CREATE_SLOT) + interval

    if wait_for > 0:
        logger.info("[Roxy] /browser/create Yêu cầu lệch giờ cao điểm, chờ %.2fs", wait_for)
        time.sleep(wait_for)


@dataclass
class RoxyOpenResult:
    profile_id: str
    raw: dict
    debugger_address: str | None = None
    webdriver_url: str | None = None
    ws_endpoint: str | None = None
    created_by_run: bool = False


def _strip_slashes(value: str) -> str:
    return str(value or "").strip().strip("/")


def _join_url(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _mask_proxy(proxy_url: str) -> str:
    parsed = urlparse(str(proxy_url or "").strip())
    if parsed.username or parsed.password:
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://***:***@{host}{port}"
    return str(proxy_url or "").strip()


def _proxy_url_to_roxy_info(proxy_url: str) -> dict:
    """
    Chuyển URL proxy trong config/proxy.py thành proxyInfo của Roxy /browser/create.

    Hỗ trợ:
      http://user:pass@host:port
      https://user:pass@host:port
      socks5://user:pass@host:port
      socks5h://user:pass@host:port  -> Phía Roxy xử lý như SOCKS5
    """
    text = str(proxy_url or "").strip()
    if not text:
        raise ValueError("Proxy trống")
    parsed = urlparse(text)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https", "socks5", "socks5h"):
        raise ValueError(f"Roxy Tạm chưa hỗ trợ giao thức proxy này: {scheme or '-'}")
    if not parsed.hostname or not parsed.port:
        raise ValueError(f"Định dạng proxy thiếu host/port: {_mask_proxy(text)}")

    protocol = {
        "http": "HTTP",
        "https": "HTTPS",
        "socks5": "SOCKS5",
        "socks5h": "SOCKS5",
    }[scheme]
    # Roxy /browser/create các trường chính thức là:
    # proxyMethod / proxyCategory / ipType / protocol / host / port / proxyUserName / proxyPassword / checkChannel
    # Trước đó dùng nhầm proxyType/proxyHost/proxyPort/proxyAccount, Roxy sẽ bỏ qua, khiến cửa sổ tạo ra thực tế không đặt proxy.
    info = {
        "moduleId": 0,
        "proxyMethod": "custom",
        "proxyCategory": protocol,
        "ipType": "IPV4",
        "protocol": protocol,
        "host": parsed.hostname,
        "port": str(parsed.port),
    }
    if parsed.username:
        info["proxyUserName"] = unquote(parsed.username)
    if parsed.password:
        info["proxyPassword"] = unquote(parsed.password)
    check_channel = str(getattr(_cfg, "ROXY_PROXY_CHECK_CHANNEL", "") or "").strip()
    if check_channel:
        info["checkChannel"] = check_channel
    return info


def _dig(payload: dict, *keys: str):
    cur = payload
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _first(payload: dict, paths: list[tuple[str, ...]]) -> str:
    for path in paths:
        value = _dig(payload, *path)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _workspace_id_value() -> str | int:
    raw = str(getattr(_cfg, "ROXY_WORKSPACE_ID", "") or "").strip()
    if not raw:
        return ""
    return int(raw) if raw.isdigit() else raw


def _project_id_value() -> str | int:
    raw = str(getattr(_cfg, "ROXY_PROJECT_ID", "") or "").strip()
    if not raw:
        return ""
    return int(raw) if raw.isdigit() else raw


def _apply_data_saver_open_args(params: dict) -> dict:
    """Tắt tải ảnh sớm trong tham số khởi động Roxy, bao phủ cả URL ảnh không có phần mở rộng.

    Network.setBlockedURLs chỉ chặn theo hậu tố URL, trong khi trình duyệt Roxy đã khởi động
    trước khi Selenium kết nối; dùng cờ Chromium để vô hiệu hóa ảnh trước request trang đầu tiên. Cờ này
    chỉ được thêm khi người dùng bật rõ chế độ tiết kiệm dung lượng và bao gồm loại image.
    """
    try:
        from config import browser as _browser_cfg

        if not bool(getattr(_browser_cfg, "BROWSER_DATA_SAVER_MODE", False)):
            return params
        raw_types = getattr(_browser_cfg, "BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES", [])
        if isinstance(raw_types, str):
            types = {item.strip().lower() for item in raw_types.replace(",", "\n").splitlines() if item.strip()}
        else:
            types = {str(item or "").strip().lower() for item in (raw_types or []) if str(item or "").strip()}
        if "image" not in types and "images" not in types and "img" not in types:
            return params

        current = params.get("args")
        if isinstance(current, (list, tuple)):
            args = list(current)
        elif current:
            args = [str(current)]
        else:
            args = []
        switch = "--blink-settings=imagesEnabled=false"
        if switch not in args:
            args.append(switch)
        params["args"] = args
    except Exception as exc:
        logger.debug("[Roxy] Thêm tham số khởi động ảnh tiết kiệm data thất bại, Tiếp tục dùng tham số gốc: %s", exc)
    return params


def _random_roxy_os() -> str:
    raw = str(getattr(_cfg, "ROXY_RANDOM_OS_CHOICES", "Windows,macOS") or "Windows,macOS")
    choices = [
        x.strip()
        for part in raw.replace("\n", ",").replace(";", ",").split(",")
        for x in [part]
        if x.strip()
    ]
    valid = {"Windows", "macOS", "Linux", "IOS", "Android"}
    choices = [x for x in choices if x in valid]
    if not choices:
        choices = ["Windows", "macOS"]
    return random.choice(choices)


def _random_roxy_profile_name() -> str:
    prefix = str(getattr(_cfg, "ROXY_PROFILE_NAME_PREFIX", "rb") or "rb").strip() or "rb"
    # Tên môi trường Roxy mỗi lần tạo đều khác: tiền tố + timestamp mili giây + 4 ký tự hex ngẫu nhiên.
    return f"{prefix}-{int(time.time() * 1000)}-{random.randrange(0x10000):04x}"


class RoxyBrowserClient:
    def __init__(self, api_base: str | None = None, token: str | None = None):
        self.api_base = (api_base or _cfg.ROXY_API_BASE).strip()
        self.token = (token if token is not None else _cfg.ROXY_API_TOKEN).strip()
        self._proxy_pool_relay = None
        self._proxy_pool_target = ""
        self.http = requests.Session()
        if self.token:
            # Tài liệu chính thức yêu cầu mọi header request API phải thêm token. Ở đây tương thích cả token / Authorization.
            self.http.headers.update({
                "token": self.token,
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            })

    @staticmethod
    def _is_retryable_error(exc: Exception) -> bool:
        text = str(exc or "").lower()
        return (
            "timeout" in text
            or "timed out" in text
            or "connection" in text
            or "temporarily" in text
            or "http 500" in text
            or "http 502" in text
            or "http 503" in text
            or "http 504" in text
            or "http 429" in text
        )

    def request(self, method: str, path: str, *, params: dict | None = None, json_body: dict | None = None) -> dict:
        url = _join_url(self.api_base, path)
        method_u = method.upper()
        is_create = str(path or "").rstrip("/").endswith("/create") or "browser/create" in str(path or "")
        if is_create:
            max_attempts = max(1, int(getattr(_cfg, "ROXY_CREATE_RETRIES", 3) or 3))
            base_delay = max(0.5, float(getattr(_cfg, "ROXY_CREATE_RETRY_DELAY", 3) or 3))
        else:
            max_attempts = max(1, int(getattr(_cfg, "ROXY_API_RETRIES", 3) or 3))
            base_delay = max(0.5, float(getattr(_cfg, "ROXY_API_RETRY_DELAY", 2) or 2))
        last_exc: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                logger.debug(
                    "[Roxy] %s %s params=%s body=%s attempt=%s/%s",
                    method, url, params, json_body, attempt, max_attempts,
                )
                resp = self.http.request(
                    method_u,
                    url,
                    params=params or None,
                    json=json_body if json_body is not None else None,
                    timeout=max(5, int(getattr(_cfg, "ROXY_SELENIUM_TIMEOUT", 90) or 90)),
                )
                text = resp.text or ""
                try:
                    payload = resp.json()
                except Exception:
                    payload = {"raw": text}
                if not (200 <= resp.status_code < 300):
                    raise RuntimeError(f"Roxy API Yêu cầu thất bại {method_u} {path} HTTP {resp.status_code}: {text[:500]}")
                if isinstance(payload, dict):
                    code = payload.get("code")
                    ok = payload.get("ok")
                    success = payload.get("success")
                    if code not in (None, 0, 200, "0", "200") and ok is not True and success is not True:
                        msg = payload.get("msg") or payload.get("message") or payload.get("error") or json.dumps(payload, ensure_ascii=False)[:500]
                        raise RuntimeError(f"Roxy API Trả về thất bại {method_u} {path}: {msg}")
                if attempt > 1:
                    logger.info("[Roxy] API Thử lại thành công: %s %s attempt=%s/%s", method_u, path, attempt, max_attempts)
                return payload if isinstance(payload, dict) else {"data": payload}
            except Exception as exc:
                last_exc = exc
                retryable = self._is_retryable_error(exc)
                if attempt >= max_attempts or not retryable:
                    raise
                delay = base_delay * attempt
                logger.warning(
                    "[Roxy] API Yêu cầu thất bại, Sẽ trong %.1fs sau dùng cùng%sthử lại: %s %s attempt=%s/%s error=%s",
                    delay,
                    " create payload/name " if is_create else "Tham số yêu cầu",
                    method_u, path, attempt, max_attempts, exc,
                )
                time.sleep(delay)
        raise last_exc or RuntimeError(f"Roxy API Yêu cầu thất bại {method_u} {path}")

    def try_request(self, method: str, path: str, *, params: dict | None = None, json_body: dict | None = None) -> tuple[bool, dict | str]:
        """Yêu cầu lỏng: dùng để dò giao diện các phiên bản Roxy khác nhau, thất bại không ném ngoại lệ."""
        try:
            return True, self.request(method, path, params=params, json_body=json_body)
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _extract_workspace_items(payload: dict) -> list[dict]:
        """Phân tích /browser/workspace: rows nhóm + danh sách dự án project_details; tương thích dự phòng đệ quy."""
        out = []

        # Cấu trúc chính thức: data.rows[].id/workspaceName/project_details[].projectId/projectName
        rows = None
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, dict):
                rows = data.get("rows") or data.get("list") or data.get("records")
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                wid = row.get("id") or row.get("workspaceId") or row.get("workspace_id")
                wname = row.get("workspaceName") or row.get("workspace_name") or row.get("name") or str(wid or "")
                projects = row.get("project_details") or row.get("projectDetails") or row.get("projects") or []
                if isinstance(projects, list) and projects:
                    for proj in projects:
                        if not isinstance(proj, dict):
                            continue
                        pid = proj.get("projectId") or proj.get("project_id") or proj.get("id")
                        pname = proj.get("projectName") or proj.get("project_name") or proj.get("name") or str(pid or "")
                        if wid:
                            out.append({
                                "id": str(wid),
                                "name": str(wname),
                                "projectId": str(pid or ""),
                                "projectName": str(pname or ""),
                                "label": f"{wname} / {pname} ({wid}/{pid})" if pid else f"{wname} ({wid})",
                                "raw": {"workspace": row, "project": proj},
                            })
                elif wid:
                    out.append({
                        "id": str(wid),
                        "name": str(wname),
                        "projectId": "",
                        "projectName": "",
                        "label": f"{wname} ({wid})",
                        "raw": row,
                    })

        if out:
            return out

        # Dự phòng: đệ quy trích cấu trúc workspace/team/company.
        def pick_id_name(item: dict) -> tuple[str, str]:
            wid = _first(item, [
                ("workspaceId",), ("workspace_id",), ("workspaceID",),
                ("teamId",), ("team_id",), ("teamID",),
                ("companyId",), ("company_id",), ("orgId",), ("org_id",),
                ("id",), ("value",), ("key",),
            ])
            name = _first(item, [
                ("workspaceName",), ("workspace_name",),
                ("teamName",), ("team_name",),
                ("companyName",), ("company_name",),
                ("orgName",), ("org_name",),
                ("name",), ("label",), ("title",), ("remark",),
            ])
            return wid, name

        def looks_like_workspace(item: dict) -> bool:
            keys = {str(k).lower() for k in item.keys()}
            joined = " ".join(keys)
            return any(x in joined for x in ("workspace", "team", "company", "org")) or ("id" in keys and "name" in keys)

        def walk(node):
            if isinstance(node, dict):
                wid, name = pick_id_name(node)
                if wid and looks_like_workspace(node):
                    out.append({"id": wid, "name": name or wid, "projectId": "", "projectName": "", "label": f"{name or wid} ({wid})", "raw": node})
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(payload)
        dedup = {}
        for item in out:
            raw_keys = {str(k).lower() for k in (item.get("raw") or {}).keys()}
            if "dirid" in raw_keys and not any(k in raw_keys for k in ("workspaceid", "teamid", "companyid")):
                continue
            key = f"{item.get('id')}::{item.get('projectId','')}"
            dedup[key] = item
        return list(dedup.values())

    def list_workspaces(self) -> dict:
        """
        Lấy danh sách team/workspace Roxy.
        Đường dẫn Roxy có thể khác giữa các phiên bản, nên thử đường dẫn cấu hình trước, rồi thử các đường dẫn phổ biến.
        """
        configured = str(getattr(_cfg, "ROXY_WORKSPACE_LIST_PATH", "") or "").strip()
        method = str(getattr(_cfg, "ROXY_WORKSPACE_LIST_METHOD", "GET") or "GET").upper()
        candidates = []
        if configured:
            candidates.append((method, configured))
        candidates.extend([
            ("GET", "/browser/workspace"),
            ("POST", "/browser/workspace"),
            ("GET", "/workspace/list"),
            ("POST", "/workspace/list"),
            ("GET", "/workspace"),
            ("POST", "/workspace"),
            ("GET", "/team/list"),
            ("POST", "/team/list"),
            ("GET", "/team"),
            ("POST", "/team"),
            ("GET", "/workspaces"),
            ("GET", "/teams"),
            ("GET", "/user/workspace/list"),
            ("POST", "/user/workspace/list"),
            ("GET", "/user/team/list"),
            ("POST", "/user/team/list"),
            ("GET", "/api/workspace/list"),
            ("POST", "/api/workspace/list"),
            ("GET", "/api/team/list"),
            ("POST", "/api/team/list"),
            ("GET", "/browser/workspace/list"),
            ("POST", "/browser/workspace/list"),
            ("GET", "/browser/team/list"),
            ("POST", "/browser/team/list"),
        ])

        errors = []
        seen = set()
        for m, path in candidates:
            key = (m, path)
            if key in seen:
                continue
            seen.add(key)
            ok, payload = self.try_request(m, path)
            if not ok:
                errors.append({"method": m, "path": path, "error": payload})
                continue
            items = self._extract_workspace_items(payload if isinstance(payload, dict) else {})
            if items:
                return {"ok": True, "path": path, "method": m, "items": items, "raw": payload}
            errors.append({"method": m, "path": path, "error": "Phản hồi không parse được danh sách team/workspace", "payload": payload})

        return {"ok": False, "items": [], "errors": errors}

    def create_profile(self, payload: dict | None = None) -> str:
        body = dict(getattr(_cfg, "ROXY_PROFILE_CREATE_PAYLOAD", {}) or {})
        if payload:
            body.update(payload)
        random_name_enabled = bool(getattr(_cfg, "ROXY_RANDOM_PROFILE_NAME_ON_CREATE", True))
        if random_name_enabled:
            # Ghi đè name cố định trong ROXY_PROFILE_CREATE_PAYLOAD, tránh tất cả cửa sổ Roxy cùng tên.
            body["name"] = _random_roxy_profile_name()
        random_os_enabled = bool(getattr(_cfg, "ROXY_RANDOM_OS_ON_CREATE", True))
        if random_os_enabled:
            # Mỗi lần tạo môi trường ngẫu nhiên Windows / macOS; ghi đè os cố định trong ROXY_PROFILE_CREATE_PAYLOAD.
            body["os"] = _random_roxy_os()
            # osVersion gắn chặt với os, khi random OS không dùng phiên bản cố định, tránh truyền phiên bản macOS cho Windows.
            body.pop("osVersion", None)
        else:
            default_os = str(getattr(_cfg, "ROXY_DEFAULT_OS", "macOS") or "macOS").strip()
            if default_os:
                # Roxy enum chính thức phân biệt chữ hoa/thường: Windows / macOS / Linux / IOS / Android.
                body.setdefault("os", default_os)
            default_os_version = str(getattr(_cfg, "ROXY_DEFAULT_OS_VERSION", "") or "").strip()
            if default_os_version:
                body.setdefault("osVersion", default_os_version)
        workspace_id = _workspace_id_value()
        if workspace_id:
            # Roxy chính thức /browser/create yêu cầu workspaceId.
            body.setdefault("workspaceId", workspace_id)
        project_id = _project_id_value()
        if project_id:
            body.setdefault("projectId", project_id)
        if bool(getattr(_cfg, "ROXY_CREATE_USE_PROXY_POOL", False)) and not body.get("proxyInfo"):
            from config import proxy as _proxy_cfg
            from core.proxy_chain import open_proxy_pool_proxy

            target_proxy = _proxy_cfg.pick_proxy()
            proxy_url, relay = open_proxy_pool_proxy(target_proxy)
            self._proxy_pool_relay = relay
            self._proxy_pool_target = str(target_proxy or "").strip()
            if proxy_url:
                proxy_info = _proxy_url_to_roxy_info(proxy_url)
                body["proxyInfo"] = proxy_info
                logger.info(
                    "[Roxy] Tạo profile bật proxy pool: target=%s transport=%s type=%s host=%s port=%s",
                    str(target_proxy or "").strip(), str(proxy_url or "").strip(),
                    proxy_info.get("protocol") or proxy_info.get("proxyCategory"),
                    proxy_info.get("host"),
                    proxy_info.get("port"),
                )
            else:
                logger.warning("[Roxy] Đã bật ROXY_CREATE_USE_PROXY_POOL, nhưng PROXY_POOL Rỗng, Lần này tạo profile không đặt proxy")
        if not body.get("workspaceId"):
            raise RuntimeError(
                "Roxy tạo profile cần workspaceId. Hãy điền ROXY_WORKSPACE_ID trong config/roxybrowser.py hoặc cấu hình RoxyBrowser của WebUI, "
                "hoặc thêm {'workspaceId': 'ID workspace'} vào ROXY_PROFILE_CREATE_PAYLOAD."
            )
        logger.info(
            "[Roxy] Tham số tạo profile: workspaceId=%s projectId=%s name=%s random_name=%s os=%s osVersion=%s random_os=%s",
            body.get("workspaceId"),
            body.get("projectId") or "-",
            body.get("name") or "-",
            random_name_enabled,
            body.get("os") or "-",
            body.get("osVersion") or "-",
            random_os_enabled,
        )
        _wait_for_create_slot()
        result = self.request(_cfg.ROXY_CREATE_METHOD, _cfg.ROXY_CREATE_PATH, json_body=body)
        profile_id = _first(result, [
            ("id",), ("dirId",), ("dir_id",), ("profile_id",), ("profileId",), ("browser_id",),
            ("data", "id"), ("data", "dirId"), ("data", "dir_id"),
            ("data", "profile_id"), ("data", "profileId"), ("data", "browser_id"),
        ])
        if not profile_id:
            raise RuntimeError(f"Roxy Tạo profile thành công nhưng chưa trả về dirId/profile_id: {result}")
        return profile_id

    @staticmethod
    def _normalize_profile_id(value: str | None) -> str:
        text = str(value or "").strip()
        # WebUI/cấu hình thủ công thường dùng - biểu thị "chưa cấu hình", ở đây thống nhất xử lý như rỗng.
        if text in ("-", "—", "无", "空", "none", "None", "null", "NULL"):
            return ""
        return text

    def open_profile(self, profile_id: str | None = None) -> RoxyOpenResult:
        with _ROXY_WINDOW_CREATE_LOCK:
            return self._open_profile_locked(profile_id)

    def _open_profile_locked(self, profile_id: str | None = None) -> RoxyOpenResult:
        one_profile = bool(getattr(_cfg, "ROXY_ONE_PROFILE_PER_ACCOUNT", True))
        configured_pid = self._normalize_profile_id(profile_id if profile_id is not None else getattr(_cfg, "ROXY_PROFILE_ID", ""))
        if one_profile and configured_pid:
            raise RuntimeError(
                "Đã bật ROXY_ONE_PROFILE_PER_ACCOUNT=True (một tài khoản một profile), "
                "không được cấu hình/truyền ROXY_PROFILE_ID cố định; hãy để trống để mỗi tài khoản tạo profile mới."
            )

        pid = configured_pid
        created_by_run = False
        if not pid:
            pid = self.create_profile()
            created_by_run = True
            logger.info("[Roxy] Đã tạo profile tạm thời: %s", pid)

        path = str(_cfg.ROXY_OPEN_PATH).format(profile_id=pid)
        params = dict(getattr(_cfg, "ROXY_OPEN_EXTRA_PARAMS", {}) or {})
        # Body chính thức Roxy /browser/open: {workspaceId, dirId, args, forceOpen, headless}
        params.setdefault("workspaceId", _workspace_id_value())
        params.setdefault("dirId", int(pid) if str(pid).isdigit() else pid)
        params.setdefault("args", [])
        params.setdefault("forceOpen", True)
        _apply_data_saver_open_args(params)
        # ROXY_OPEN_HEADLESS là công tắc tường minh, độ ưu tiên phải cao hơn ROXY_OPEN_EXTRA_PARAMS,
        # Nếu không, headless=False còn sót trong extra sẽ khiến WebUI sau khi lưu headless vẫn bật cửa sổ.
        params["headless"] = bool(getattr(_cfg, "ROXY_OPEN_HEADLESS", False))
        logger.info("[Roxy] open tham số: profile=%s headless=%s keep_open=%s", pid, params.get("headless"), getattr(_cfg, "ROXY_KEEP_BROWSER_OPEN", False))
        result = self.request(
            _cfg.ROXY_OPEN_METHOD,
            path,
            params=params if _cfg.ROXY_OPEN_METHOD.upper() == "GET" else None,
            json_body=params if _cfg.ROXY_OPEN_METHOD.upper() != "GET" else None,
        )
        debugger_address = self._extract_debugger_address(result)
        logger.info("[Roxy] open Trả về tóm tắt: debugger=%s raw=%s", debugger_address, json.dumps(result, ensure_ascii=False)[:800])
        webdriver_url = _first(result, [
            ("webdriver",), ("webDriver",), ("webdriver_url",), ("webdriverUrl",),
            ("selenium",), ("selenium_url",), ("seleniumUrl",),
            ("data", "webdriver"), ("data", "webDriver"), ("data", "webdriver_url"), ("data", "webdriverUrl"),
            ("data", "selenium"), ("data", "selenium_url"), ("data", "seleniumUrl"),
        ]) or None
        ws_endpoint = _first(result, [
            ("ws",), ("wsEndpoint",), ("ws_endpoint",), ("debuggerWsUrl",),
            ("data", "ws"), ("data", "wsEndpoint"), ("data", "ws_endpoint"), ("data", "debuggerWsUrl"),
        ]) or None
        if not debugger_address and not webdriver_url:
            raise RuntimeError(f"Roxy Đã mở profile nhưng chưa trả về Selenium/Địa chỉ debug, Hãy kiểm tra ROXY_OPEN_PATH hoặc phản hồi API: {result}")
        if self._proxy_pool_target:
            result = dict(result)
            result["proxy_pool_target"] = self._proxy_pool_target
        return RoxyOpenResult(
            pid,
            result,
            debugger_address=debugger_address,
            webdriver_url=webdriver_url,
            ws_endpoint=ws_endpoint,
            created_by_run=created_by_run,
        )

    def close_profile(self, profile_id: str) -> None:
        if not profile_id:
            return
        path = str(_cfg.ROXY_CLOSE_PATH).format(profile_id=profile_id)
        try:
            body = {
                "workspaceId": _workspace_id_value(),
                "dirId": int(profile_id) if str(profile_id).isdigit() else profile_id,
            }
            self.request(
                _cfg.ROXY_CLOSE_METHOD,
                path,
                params=body if str(_cfg.ROXY_CLOSE_METHOD).upper() == "GET" else None,
                json_body=body if str(_cfg.ROXY_CLOSE_METHOD).upper() != "GET" else None,
            )
            logger.info("[Roxy] Đã đóng profile: %s", profile_id)
        except Exception as exc:
            logger.warning("[Roxy] Đóng profile thất bại: %s", exc)

    def delete_profile(self, profile_id: str) -> None:
        if not profile_id:
            return
        path = str(getattr(_cfg, "ROXY_DELETE_PATH", "/browser/delete")).format(profile_id=profile_id)
        method = str(getattr(_cfg, "ROXY_DELETE_METHOD", "POST") or "POST")
        try:
            body = {
                "workspaceId": _workspace_id_value(),
                "dirIds": [int(profile_id) if str(profile_id).isdigit() else profile_id],
            }
            self.request(
                method,
                path,
                params=body if method.upper() == "GET" else None,
                json_body=body if method.upper() != "GET" else None,
            )
            logger.info("[Roxy] Đã xóa profile: %s", profile_id)
        except Exception as exc:
            logger.warning("[Roxy] Xóa profile thất bại: %s", exc)

    def cleanup_profile(self, opened: RoxyOpenResult | None) -> None:
        """Dọn dẹp khi kết thúc nhiệm vụ: đóng cửa sổ; khi một số một môi trường thì xóa Profile đã tạo trong vòng này."""
        keep_open = bool(getattr(_cfg, "ROXY_KEEP_BROWSER_OPEN", False))
        try:
            if not opened or not opened.profile_id:
                return
            if not keep_open:
                self.close_profile(opened.profile_id)

            should_delete = (
                bool(getattr(_cfg, "ROXY_ONE_PROFILE_PER_ACCOUNT", True))
                and bool(getattr(_cfg, "ROXY_DELETE_PROFILE_AFTER_RUN", True))
                and bool(opened.created_by_run)
            )
            if should_delete:
                # Trước khi xóa cố gắng đảm bảo đã đóng; nếu keep_open=True thì không xóa, tiện debug giữ hiện trường.
                if keep_open:
                    logger.info("[Roxy] ROXY_KEEP_BROWSER_OPEN=True, Bỏ qua xóa profile: %s", opened.profile_id)
                    return
                self.delete_profile(opened.profile_id)
        finally:
            if not keep_open:
                self.close_proxy_pool_relay()

    def close_proxy_pool_relay(self) -> None:
        relay, self._proxy_pool_relay = self._proxy_pool_relay, None
        if relay is not None:
            if relay.last_error:
                logger.warning(
                    "[Roxy] Lỗi gần nhất chuỗi proxy: target=%s upstream=%s error=%s",
                    _mask_proxy(self._proxy_pool_target),
                    _mask_proxy(getattr(relay.upstream, "raw", "")),
                    relay.last_error,
                )
            relay.close()

    def proxy_transport_snapshot(self) -> dict | None:
        """Trả về toàn bộ lưu lượng trình duyệt Roxy truyền qua chuỗi proxy cục bộ trong vòng này."""
        relay = self._proxy_pool_relay
        if relay is None:
            return None
        try:
            return relay.traffic_snapshot()
        except Exception:
            return None

    @staticmethod
    def _extract_debugger_address(payload: dict) -> str | None:
        value = _first(payload, [
            ("debuggerAddress",), ("debugger_address",), ("debugAddress",),
            ("debuggingPortUrl",), ("debugging_port_url",),
            ("remoteDebuggingAddress",), ("remote_debugging_address",),
            ("http",), ("debugHttp",), ("debug_http",),
            ("data", "debuggerAddress"), ("data", "debugger_address"), ("data", "debugAddress"),
            ("data", "debuggingPortUrl"), ("data", "debugging_port_url"),
            ("data", "remoteDebuggingAddress"), ("data", "remote_debugging_address"),
            ("data", "http"), ("data", "debugHttp"), ("data", "debug_http"),
        ])
        if value:
            value = value.strip()
            # Tương thích http://127.0.0.1:xxxx / 127.0.0.1:xxxx / :xxxx / 9222
            value = value.replace("http://", "").replace("https://", "").strip("/")
            if value.startswith(":") and value[1:].isdigit():
                return f"127.0.0.1{value}"
            if value.isdigit():
                return f"127.0.0.1:{value}"
            if ":" in value and not value.startswith(":"):
                return value
        port = _first(payload, [
            ("debuggingPort",), ("debugging_port",), ("debug_port",), ("port",),
            ("data", "debuggingPort"), ("data", "debugging_port"), ("data", "debug_port"), ("data", "port"),
        ])
        if port:
            port = str(port).strip()
            if port.startswith(":"):
                port = port[1:]
            if port.isdigit():
                return f"127.0.0.1:{port}"
        return None

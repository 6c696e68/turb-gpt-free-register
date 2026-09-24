"""
Script tự đăng ký Codex Agent Identity
by 久雾

Quy trình:
1. Lấy thông tin tài khoản qua ChatGPT session JWT
2. Sinh cặp khóa Ed25519
3. Đăng ký agent trên auth.openai.com
4. Sinh auth.json dùng được cho Codex CLI

Phụ thuộc: curl_cffi, cryptography
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import random
import string
import sys
import time
import uuid
from typing import Any

from curl_cffi import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    load_pem_private_key,
)


# ============================================================
#  Hằng số
# ============================================================

AUTHAPI_BASE = "https://auth.openai.com/api/accounts"
CHATGPT_BASE = "https://chatgpt.com"
IMPERSONATE = "chrome"

CHROME_VERSION = "146"
USER_AGENT = (
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    f"AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/{CHROME_VERSION}.0.0.0 Safari/537.36"
)

# Thông tin phiên bản Codex CLI agent
AGENT_VERSION = "0.138.0-alpha.6"
AGENT_HARNESS_ID = "codex-cli"
RUNNING_LOCATION = "local"


# ============================================================
#  Nhật ký
# ============================================================

logger = logging.getLogger(__name__)


def _log(step: str, msg: str, level: str = "INFO") -> None:
    """Thống nhất dùng logging, tránh lẫn stdout màu ANSI vào nhật ký WebUI/nhiệm vụ."""
    text = f"[CodexAgent][{step}] {msg}"
    if level in {"WARN", "WARNING"}:
        logger.warning(text)
    elif level == "ERROR":
        logger.error(text)
    else:
        logger.info(text)


def _banner(title: str) -> None:
    logger.info("[CodexAgent] %s", title)


def _fingerprint(value: str, length: int = 12) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:length]


# ============================================================
#  Tạo cặp khóa Ed25519
# ============================================================

def generate_ed25519_keypair() -> tuple[str, str]:
    """
    Tạo cặp khóa Ed25519.

    :return: (private_key_pkcs8_base64, public_key_ssh)
    """
    private_key = Ed25519PrivateKey.generate()

    # Khóa riêng định dạng PKCS8 DER → base64
    pkcs8_der = private_key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    private_key_b64 = base64.b64encode(pkcs8_der).decode()

    # Byte khóa công khai gốc
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    # Xây dựng định dạng khóa công khai SSH: ssh-ed25519 base64(blob)
    ssh_header = b"ssh-ed25519"
    blob = bytearray()
    blob.extend(len(ssh_header).to_bytes(4, "big"))
    blob.extend(ssh_header)
    blob.extend(len(pub_bytes).to_bytes(4, "big"))
    blob.extend(pub_bytes)
    ssh_b64 = base64.b64encode(bytes(blob)).decode()
    public_key_ssh = f"ssh-ed25519 {ssh_b64}"

    return private_key_b64, public_key_ssh


# ============================================================
#  Giải mã JWT (không xác minh chữ ký, chỉ trích xuất claims)
# ============================================================

def decode_jwt_claims(jwt_token: str) -> dict[str, Any]:
    """
    Giải mã JWT payload (không xác minh chữ ký).

    :param jwt_token: chuỗi JWT
    :return: claims dict
    """
    parts = jwt_token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    # JWT payload là mã hóa base64url
    payload_b64 = parts[1]
    # Bổ sung padding
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding

    payload_bytes = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload_bytes)


# ============================================================
#  Lấy Session
# ============================================================

def get_session_from_cookies(cookies: dict[str, str]) -> dict[str, Any]:
    """
    Dùng cookies gọi /api/auth/session để lấy accessToken và thông tin tài khoản.

    :param cookies: dict cookies của chatgpt.com
    :return: dữ liệu session
    """
    r = requests.get(
        f"{CHATGPT_BASE}/api/auth/session",
        cookies=cookies,
        headers={"user-agent": USER_AGENT},
        impersonate=IMPERSONATE,
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def get_session_from_access_token(access_token: str) -> dict[str, Any]:
    """
    Nếu đã có JWT access token, giải mã trực tiếp để lấy thông tin.

    :param access_token: ChatGPT session JWT
    :return: dict chứa accessToken, accountId, email, userId, planType
    """
    claims = decode_jwt_claims(access_token)
    auth_info = claims.get("https://api.openai.com/auth", {})
    profile = claims.get("https://api.openai.com/profile", {})

    return {
        "accessToken": access_token,
        "accountId": auth_info.get("chatgpt_account_id", ""),
        "userId": auth_info.get("chatgpt_user_id", ""),
        "email": profile.get("email", ""),
        "planType": auth_info.get("chatgpt_plan_type", "free"),
    }


def _agent_headers(access_token: str, env: Any | None = None) -> dict[str, str]:
    """Tạo header yêu cầu Agent API; khi có BrowserSession thì dùng hồ sơ vân tay độc lập của tài khoản đó."""
    if env is not None and hasattr(env, "_get_common_headers"):
        headers = env._get_common_headers()
    else:
        headers = {"User-Agent": USER_AGENT}
    headers.update({
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
    })
    if env is not None:
        try:
            headers["oai-device-id"] = env.device_id
            headers["oai-language"] = env.navigator_language()
            if hasattr(env, "_attach_auth_rum_headers"):
                env._attach_auth_rum_headers(headers)
        except Exception:
            pass
    return headers


def _agent_post(url: str, *, access_token: str, payload: dict[str, Any], env: Any | None = None, timeout: int = 15):
    """Dùng BrowserSession độc lập hoặc curl_cffi mặc định để gửi Agent API POST."""
    headers = _agent_headers(access_token, env=env)
    if env is not None and hasattr(env, "session"):
        return env.session.post(url, headers=headers, json=payload, timeout=timeout)
    return requests.post(url, headers=headers, json=payload, impersonate=IMPERSONATE, timeout=timeout)


# ============================================================
#  Đăng ký Agent
# ============================================================

def register_agent(
    access_token: str,
    public_key_ssh: str,
    env: Any | None = None,
    timeout: int = 15,
    display_name: str | None = None,
) -> str:
    """
    Đăng ký agent trên auth.openai.com.

    :param access_token: ChatGPT session JWT
    :param public_key_ssh: Khóa công khai Ed25519 định dạng SSH
    :return: agent_runtime_id
    """
    name = str(display_name or "").strip() or _random_agent_display_name()
    payload = {
        "abom": {
            "agent_version": AGENT_VERSION,
            "agent_harness_id": AGENT_HARNESS_ID,
            "running_location": RUNNING_LOCATION,
            # Kịch bản OpenAI Agent cũng dùng tên ngẫu nhiên vòng này, tránh cố định cùng một tên hiển thị.
            "display_name": name,
            "agent_name": name,
        },
        "agent_public_key": public_key_ssh,
        "display_name": name,
        "agent_name": name,
        "name": name,
    }

    r = _agent_post(
        f"{AUTHAPI_BASE}/v1/agent/register",
        access_token=access_token,
        env=env,
        timeout=timeout,
        payload=payload,
    )

    # Tương thích trường hợp API OpenAI kiểm tra nghiêm các trường lạ: nếu trường đặt tên không được chấp nhận, fallback về giao thức gốc.
    if r.status_code == 400 and any(x in (r.text or "").lower() for x in ("unknown", "unrecognized", "extra", "invalid")):
        _log("Step 3", f"OpenAI Agent API đăng ký không chấp nhận trường tên, quay về bản gốc payload: {r.text[:180]}", "WARN")
        r = _agent_post(
            f"{AUTHAPI_BASE}/v1/agent/register",
            access_token=access_token,
            env=env,
            timeout=timeout,
            payload={
                "abom": {
                    "agent_version": AGENT_VERSION,
                    "agent_harness_id": AGENT_HARNESS_ID,
                    "running_location": RUNNING_LOCATION,
                },
                "agent_public_key": public_key_ssh,
            },
        )

    if r.status_code != 200:
        raise RuntimeError(f"Agent registration failed: {r.status_code} {r.text}")

    data = r.json()
    agent_runtime_id = data.get("agent_runtime_id")
    if not agent_runtime_id:
        raise RuntimeError(f"No agent_runtime_id in response: {data}")

    return agent_runtime_id


# ============================================================
#  Đăng ký Task (xác minh tính khả dụng của cặp khóa)
# ============================================================

def register_task(
    access_token: str,
    agent_runtime_id: str,
    private_key_pkcs8_b64: str,
    env: Any | None = None,
    timeout: int = 15,
) -> str:
    """
    Đăng ký task trên auth.openai.com (xác minh cặp khóa khả dụng).
    Codex CLI khi khởi động sẽ tự thực hiện bước này.

    :param access_token: ChatGPT session JWT (chỉ dùng để xác minh; Codex CLI thực tế ký bằng khóa)
    :param agent_runtime_id: ID runtime của agent
    :param private_key_pkcs8_b64: khóa riêng PKCS8 base64
    :return: encrypted_task_id
    """
    # Tải khóa riêng
    pkcs8_der = base64.b64decode(private_key_pkcs8_b64)
    pem = b"-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(pkcs8_der) + b"-----END PRIVATE KEY-----\n"
    private_key = load_pem_private_key(pem, password=None)

    # Payload chữ ký: {agent_runtime_id}:{timestamp}
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = f"{agent_runtime_id}:{timestamp}"
    signature = private_key.sign(payload.encode())
    signature_b64 = base64.b64encode(signature).decode()

    r = _agent_post(
        f"{AUTHAPI_BASE}/v1/agent/{agent_runtime_id}/task/register",
        access_token=access_token,
        env=env,
        timeout=timeout,
        payload={
            "timestamp": timestamp,
            "signature": signature_b64,
        },
    )

    if r.status_code != 200:
        raise RuntimeError(f"Task registration failed: {r.status_code} {r.text}")

    data = r.json()
    return data.get("encrypted_task_id", "")


# ============================================================
#  Tạo auth.json
# ============================================================

def _random_agent_display_name() -> str:
    """Tạo tên Agent ngẫu nhiên, tránh để tên tài khoản sub2api lộ trực tiếp tiền tố email."""
    adjectives = [
        "Amber", "Blue", "Cedar", "Delta", "Echo", "Falcon", "Golden", "Harbor",
        "Ivory", "Jade", "Lunar", "Nova", "Orion", "Pine", "Quartz", "River",
        "Silver", "Summit", "Vertex", "Willow",
    ]
    nouns = [
        "Agent", "Bridge", "Comet", "Drift", "Field", "Garden", "Harbor", "Island",
        "Kernel", "Lantern", "Matrix", "Node", "Orbit", "Pilot", "Relay", "Signal",
        "Stone", "Tower", "Vector", "Worker",
    ]
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"{random.choice(adjectives)} {random.choice(nouns)} {suffix}"


def generate_auth_json(
    agent_runtime_id: str,
    private_key_pkcs8_b64: str,
    account_id: str,
    chatgpt_user_id: str,
    email: str,
    plan_type: str = "free",
    chatgpt_account_is_fedramp: bool = False,
    display_name: str | None = None,
) -> dict[str, Any]:
    """
    Tạo auth.json cho Codex CLI.

    :return: auth.json dict
    """
    return {
        "auth_mode": "agent_identity",
        "agent_identity": {
            "agent_runtime_id": agent_runtime_id,
            "agent_private_key": private_key_pkcs8_b64,
            "account_id": account_id,
            "chatgpt_user_id": chatgpt_user_id,
            "email": email,
            "name": email,
            "plan_type": plan_type,
            "chatgpt_account_is_fedramp": chatgpt_account_is_fedramp,
        },
    }


# ============================================================
#  Kết nối sub2api
# ============================================================

def build_sub2api_account_entry(
    auth_json: dict[str, Any],
    *,
    proxy_key: str | None = None,
) -> dict[str, Any]:
    """Chuyển Codex Agent Identity auth.json thành mục accounts[] của sub2api."""
    identity = auth_json.get("agent_identity") if isinstance(auth_json, dict) else None
    if not isinstance(identity, dict):
        raise ValueError("auth_json thiếu agent_identity")

    agent_runtime_id = str(identity.get("agent_runtime_id") or "").strip()
    agent_private_key = str(identity.get("agent_private_key") or "").strip()
    account_id = str(identity.get("account_id") or "").strip()
    chatgpt_user_id = str(identity.get("chatgpt_user_id") or "").strip()
    email = str(identity.get("email") or "").strip()
    display_name = email or str(identity.get("name") or identity.get("display_name") or "").strip() or f"agent-{agent_runtime_id[:8]}"
    plan_type = str(identity.get("plan_type") or "free").strip() or "free"
    if not agent_runtime_id or not agent_private_key:
        raise ValueError("agent_identity thiếu agent_runtime_id/agent_private_key")

    entry = {
        "name": display_name,
        "platform": "openai",
        "type": "agent_identity",
        "credentials": {
            "agent_runtime_id": agent_runtime_id,
            "agent_private_key": agent_private_key,
            "account_id": account_id,
            "chatgpt_account_id": account_id,
            "chatgpt_user_id": chatgpt_user_id,
            "email": email,
            "name": email,
            "plan_type": plan_type,
            "chatgpt_account_is_fedramp": bool(identity.get("chatgpt_account_is_fedramp", False)),
        },
        "extra": {
            "email": email,
            "account_id": account_id,
            "chatgpt_account_id": account_id,
            "chatgpt_user_id": chatgpt_user_id,
            "agent_runtime_id": agent_runtime_id,
            "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "codex_agent",
        },
        "concurrency": 10,
        "priority": 1,
        "rate_multiplier": 1,
        "auto_pause_on_expired": True,
    }
    if proxy_key:
        entry["proxy_key"] = str(proxy_key)
    return entry


def _sub2api_dedupe_key(entry: dict[str, Any]) -> str:
    credentials = entry.get("credentials") if isinstance(entry.get("credentials"), dict) else {}
    extra = entry.get("extra") if isinstance(entry.get("extra"), dict) else {}
    agent_runtime_id = credentials.get("agent_runtime_id") or extra.get("agent_runtime_id")
    if agent_runtime_id:
        return f"agent:{agent_runtime_id}"
    user_id = credentials.get("chatgpt_user_id") or extra.get("chatgpt_user_id")
    account_id = credentials.get("chatgpt_account_id") or credentials.get("account_id") or extra.get("chatgpt_account_id") or extra.get("account_id")
    if user_id and account_id:
        return f"account-user:{user_id}|{account_id}"
    email = credentials.get("email") or extra.get("email")
    if email:
        return f"email:{email}"
    return ""


def upsert_sub2api_account(
    auth_json: dict[str, Any],
    output_path: str | os.PathLike[str],
    *,
    proxy_key: str | None = None,
) -> dict[str, Any]:
    """Thêm/cập nhật Agent Token vào sub2api.json."""
    path = os.fspath(output_path)
    data: dict[str, Any]
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        if not isinstance(loaded, dict):
            raise ValueError("sub2api Nút gốc file cấu hình phải là đối tượng")
        data = loaded
    else:
        data = {}

    accounts = data.setdefault("accounts", [])
    if not isinstance(accounts, list):
        raise ValueError("sub2api trong cấu hình accounts phải là mảng")
    proxies = data.setdefault("proxies", [])
    if not isinstance(proxies, list):
        raise ValueError("sub2api trong cấu hình proxies phải là mảng")
    if proxy_key and not proxies:
        data["proxies"] = [{"proxy_key": str(proxy_key)}]

    incoming = build_sub2api_account_entry(auth_json, proxy_key=proxy_key)
    key = _sub2api_dedupe_key(incoming)
    updated = False
    for idx, existing in enumerate(accounts):
        if isinstance(existing, dict) and key and _sub2api_dedupe_key(existing) == key:
            merged = dict(existing)
            merged.update(incoming)
            # Giữ các tham số lập lịch/khóa proxy đã điều chỉnh thủ công.
            for keep in ("concurrency", "priority", "rate_multiplier", "auto_pause_on_expired", "proxy_key"):
                if keep in existing and (keep != "proxy_key" or not proxy_key):
                    merged[keep] = existing[keep]
            accounts[idx] = merged
            updated = True
            break
    if not updated:
        accounts.append(incoming)

    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, path)
    return {
        "ok": True,
        "updated": updated,
        "added": not updated,
        "path": os.path.abspath(path),
        "total": len(accounts),
        "email": incoming.get("extra", {}).get("email"),
        "dedupe_key": key,
    }


def upload_sub2api_account(
    auth_json: dict[str, Any],
    api_url: str,
    *,
    api_token: str | None = None,
    auth_header: str = "Authorization",
    auth_prefix: str = "Bearer",
    payload_mode: str = "accounts",
    proxy_key: str | None = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Tải lên/nhập Agent Token trực tiếp qua HTTP API sub2api.

    Cách dùng chuẩn Wei-Shaw/sub2api:
      POST /api/v1/admin/accounts/import/codex-session
      {"contents":["<auth.json>"],"update_existing":true,...}

    payload_mode:
      - codex_session_import: API nhập Codex Session/Agent Identity gốc của sub2api
      - account:  POST trực tiếp một đối tượng account
      - accounts: POST {"accounts": [account]}
      - config:   POST {"accounts": [account], "proxies": [...]}
    """
    url = str(api_url or "").strip()
    if not url:
        raise ValueError("SUB2API_API_BASE Rỗng, không thể tải lên đến sub2api")

    mode = str(payload_mode or "accounts").strip().lower()
    incoming: dict[str, Any] | None = None
    if mode in {"codex_session_import", "codex-session-import", "import_codex_session"}:
        identity = auth_json.get("agent_identity") if isinstance(auth_json, dict) else {}
        payload = {
            "contents": [json.dumps(auth_json, ensure_ascii=False)],
            "name": str((identity or {}).get("email") or "").strip() or str((identity or {}).get("name") or "").strip() or _random_agent_display_name(),
            "update_existing": True,
            "concurrency": 3,
            "priority": 50,
            "confirm_mixed_channel_risk": True,
        }
    elif mode == "config":
        incoming = build_sub2api_account_entry(auth_json, proxy_key=proxy_key)
        payload = {"accounts": [incoming], "proxies": ([{"proxy_key": str(proxy_key)}] if proxy_key else [])}
    elif mode == "account":
        incoming = build_sub2api_account_entry(auth_json, proxy_key=proxy_key)
        payload = incoming
    else:
        incoming = build_sub2api_account_entry(auth_json, proxy_key=proxy_key)
        payload = {"accounts": [incoming]}

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "turb-gpt-free-register/sub2api",
    }
    token = str(api_token or "").strip()
    header_name = str(auth_header or "Authorization").strip() or "Authorization"
    prefix = str(auth_prefix or "").strip()
    if token:
        headers[header_name] = f"{prefix} {token}".strip() if prefix else token

    resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    status = int(getattr(resp, "status_code", 0) or 0)
    text = getattr(resp, "text", "") or ""
    try:
        body = resp.json()
    except Exception:
        body = {"text": text[:1000]}
    if status < 200 or status >= 300:
        raise RuntimeError(f"sub2api tải lên thất bại HTTP {status}: {text[:800]}")

    return {
        "ok": True,
        "uploaded": True,
        "url": url,
        "status_code": status,
        "payload_mode": mode,
        "email": (incoming or {}).get("extra", {}).get("email") or (
            (auth_json.get("agent_identity") or {}).get("email") if isinstance(auth_json, dict) else None
        ),
        "dedupe_key": _sub2api_dedupe_key(incoming) if incoming else (
            (auth_json.get("agent_identity") or {}).get("account_id") if isinstance(auth_json, dict) else None
        ),
        "response": body,
    }


# ============================================================
#  Quy trình hoàn chỉnh
# ============================================================

def create_codex_agent_identity(
    access_token: str,
    output_path: str | None = None,
    verify_task: bool = True,
    env: Any | None = None,
    timeout: int = 15,
) -> dict[str, Any]:
    """
    Quy trình đầy đủ: tạo Codex Agent Identity auth.json từ ChatGPT session JWT.

    :param access_token: ChatGPT session JWT (accessToken lấy từ /api/auth/session)
    :param output_path: đường dẫn xuất auth.json tùy chọn; không truyền thì chỉ trả object trong bộ nhớ
    :param verify_task: có xác minh đăng ký task hay không (tùy chọn)
    :return: dict auth.json
    """
    _banner("Codex Agent Identity bắt đầu đăng ký")

    # Step 1: Giải mã JWT lấy thông tin tài khoản
    _log("Step 1", "giải mã JWT lấy thông tin tài khoản...")
    session = get_session_from_access_token(access_token)
    account_id = session["accountId"]
    chatgpt_user_id = session["userId"]
    email = session["email"]
    plan_type = session["planType"]

    if not account_id or not chatgpt_user_id:
        raise RuntimeError(f"JWT thiếu trường bắt buộc: account_id={account_id}, user_id={chatgpt_user_id}")

    _log("Step 1", f"account_id={account_id}", "OK")
    _log("Step 1", f"user_id={chatgpt_user_id}", "OK")
    _log("Step 1", f"email={email}", "OK")
    _log("Step 1", f"plan_type={plan_type}", "OK")

    # Step 2: Tạo cặp khóa Ed25519
    _log("Step 2", "tạo Ed25519 cặp khóa...")
    private_key_b64, public_key_ssh = generate_ed25519_keypair()
    _log("Step 2", "Ed25519 đã tạo khóa riêng (không xuất nội dung khóa riêng)", "OK")
    _log("Step 2", f"public_key_fingerprint={_fingerprint(public_key_ssh)}", "OK")

    # Step 3: Đăng ký agent
    agent_display_name = _random_agent_display_name()
    _log("Step 3", f"tại auth.openai.com đăng ký agent, display_name={agent_display_name}...")
    agent_runtime_id = register_agent(access_token, public_key_ssh, env=env, timeout=timeout, display_name=agent_display_name)
    _log("Step 3", f"agent_runtime_id={agent_runtime_id}", "OK")

    # Step 4: Xác minh đăng ký task (tùy chọn)
    if verify_task:
        _log("Step 4", "Xác minh task đăng ký...")
        try:
            task_id = register_task(access_token, agent_runtime_id, private_key_b64, env=env, timeout=timeout)
            _log("Step 4", f"task_id_fingerprint={_fingerprint(task_id)}", "OK")
        except Exception as e:
            _log("Step 4", f"Xác minh thất bại (không ảnh hưởng auth.json): {e}", "WARN")

    # Step 5: Tạo auth.json
    _log("Step 5", "tạo auth.json...")
    auth_json = generate_auth_json(
        agent_runtime_id=agent_runtime_id,
        private_key_pkcs8_b64=private_key_b64,
        account_id=account_id,
        chatgpt_user_id=chatgpt_user_id,
        email=email,
        plan_type=plan_type,
        chatgpt_account_is_fedramp=False,
        display_name=email,
    )

    if output_path:
        _log("Step 5", "Đã bỏ qua đường dẫn xuất cục bộ, thông tin xác thực do SQLite lưu bền vững", "OK")
    else:
        _log("Step 5", "auth.json Đã trả về đối tượng trong bộ nhớ, do SQLite lưu bền vững", "OK")

    return auth_json


# ============================================================
#  Điểm vào
# ============================================================

def main() -> None:
    """
    Cách dùng:

    1. Truyền trực tiếp JWT:
       python codex_agent.py --token "eyJhbGci..."

    2. Truyền file JSON (chứa accessToken):
       python codex_agent.py --file session.json

    3. Nhập tương tác:
       python codex_agent.py
    """

    import argparse

    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    parser = argparse.ArgumentParser(description="Codex Agent Identity tự động đăng ký")
    parser.add_argument("--token", type=str, help="ChatGPT session JWT (accessToken)")
    parser.add_argument("--file", type=str, help="bao gồm accessToken của JSON đường dẫn file")
    parser.add_argument("--output", "-o", type=str, default=None, help="đường dẫn xuất tuỳ chọn; mặc định chỉ trả về và do SQLite lưu")
    parser.add_argument("--no-verify", action="store_true", help="Bỏ qua task xác minh đăng ký")
    args = parser.parse_args()

    access_token = None

    if args.token:
        access_token = args.token
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            data = json.load(f)
            access_token = data.get("accessToken") or data.get("access_token")
    else:
        # Nhập liệu tương tác
        print("Vui lòng nhập ChatGPT session JWT (accessToken): ")
        print(" (từ chatgpt.com /api/auth/session lấy)")
        access_token = input("> ").strip()

    if not access_token:
        print("lỗi: chưa cung cấp access_token")
        sys.exit(1)

    create_codex_agent_identity(
        access_token=access_token,
        output_path=args.output,
        verify_task=not args.no_verify,
    )


if __name__ == "__main__":
    main()

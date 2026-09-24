# -*- coding: utf-8 -*-
"""ChatGPT tài khoảngói/dùng thửđiều kiệntruy vấn。"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import random
import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import quote, urlparse

from core.session import BrowserSession, close_browser_session

logger = logging.getLogger(__name__)

ACCOUNTS_CHECK_PATH = "/backend-api/accounts/check/v4-2023-04-27"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def normalize_token(token: str) -> str:
    token = (token or "").strip().strip('"').strip("'")
    if token.lower().startswith("authorization:"):
        token = token.split(":", 1)[1].strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token


def _mask_proxy(proxy: str) -> str:
    """trả vềcó thể dùng chonhật ký/API kết kết quả proxytrích cần ，không lộ lộ người dùngtên và mật khẩu。"""
    value = str(proxy or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        scheme = f"{parsed.scheme}://" if parsed.scheme else ""
        auth = "***:***@" if parsed.username or parsed.password else ""
        return f"{scheme}{auth}{host}{port}" or "***"
    except Exception:
        return "***"


def _proxy_lines(value: Any) -> list[str]:
    """kiêm dung .env nhiều dòng proxyvà cũ đơn dòng proxygiá trị 。"""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [line.strip() for line in str(value).splitlines() if line.strip()]


def _local_proxy_status(proxy: str) -> tuple[bool, bool, str | None]:
    """kiểm travề vòng proxycổng；không proxy localkhông làm trước dò đo ，tránhmức ngoài mạngrequest。"""
    value = str(proxy or "").strip()
    if not value:
        return False, False, None
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname or ""
        is_loopback = host.lower() == "localhost"
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            return False, True, None
        if not parsed.port:
            return True, False, "Proxy local chưa cấu hình cổng"
        try:
            with socket.create_connection((host, parsed.port), timeout=0.5):
                return True, True, None
        except OSError as exc:
            return True, False, f"Proxy local {host}:{parsed.port} chưa lắng nghe ({type(exc).__name__}）"
    except Exception as exc:
        return False, False, f"Parse địa chỉ proxy thất bại ({type(exc).__name__}）"


def open_plan_check_proxy(route: dict, selected_proxy: str, *, timeout: float):
    """trả vềthực tếrequestproxy；cấu hình upstream khikhởi độnglocal HTTP CONNECT tiếp 。"""
    selected_proxy = str(selected_proxy or "").strip()
    upstream = str(route.get("upstream_proxy") or "").strip()
    if selected_proxy and upstream:
        from core.proxy_chain import ProxyChainRelay

        relay = ProxyChainRelay(selected_proxy, upstream, timeout=timeout).start()
        return relay.proxy_url, relay
    return selected_proxy, None


def resolve_plan_check_route(explicit_proxy: Optional[str] = None) -> dict:
    """parsegóitruy vấn thực tếmạngđường đường 。

explicit_proxy không là None khibảng hiện API điều chỉnh dùng phía rõ xác nhận phủcấu hình；trống ký tự ký hiệu chuỗi thay bảng kết nối trực tiếp。
"""
    if explicit_proxy is not None:
        selected = str(explicit_proxy or "").strip()
        return {
            "proxy": selected,
            "proxy_mode": "request",
            "network_route": "proxy" if selected else "direct",
            "proxy_used": _mask_proxy(selected) or None,
            "upstream_proxy": "",
            "upstream_proxy_used": None,
            "proxy_fallback_reason": None,
        }

    from config import proxy as proxy_cfg

    mode = str(getattr(proxy_cfg, "PLAN_CHECK_PROXY_MODE", "auto") or "auto").strip().lower()
    if mode not in {"auto", "proxy", "direct"}:
        raise ValueError(f"PLAN_CHECK_PROXY_MODE={mode!r} không hợp lệ, chọn auto / proxy / direct")
    if mode == "direct":
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct",
            "proxy_used": None,
            "upstream_proxy": "",
            "upstream_proxy_used": None,
            "proxy_fallback_reason": None,
        }

    candidates = _proxy_lines(getattr(proxy_cfg, "PLAN_CHECK_PROXY", ""))
    # 专用代理配置为代理池时，每次新的套餐查询随机选择一个；
    # 若未配置专用池，则继续从通用 PROXY_POOL 随机选择。
    selected = random.choice(candidates) if candidates else str(proxy_cfg.pick_proxy() or "").strip()
    if not selected:
        if mode == "proxy":
            raise ValueError("Chế độ mạng truy vấn gói là proxy nhưng chưa cấu hình PLAN_CHECK_PROXY hoặc PROXY_POOL")
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct",
            "proxy_used": None,
            "upstream_proxy": "",
            "upstream_proxy_used": None,
            "proxy_fallback_reason": "Chưa cấu hình proxy hoặc pool proxy cho truy vấn gói",
        }

    is_local, available, reason = _local_proxy_status(selected)
    if mode == "auto" and is_local and not available:
        return {
            "proxy": "",
            "proxy_mode": mode,
            "network_route": "direct_fallback",
            "proxy_used": _mask_proxy(selected),
            "upstream_proxy": "",
            "upstream_proxy_used": None,
            "proxy_fallback_reason": reason,
        }
    upstream = str(getattr(proxy_cfg, "PLAN_CHECK_UPSTREAM_PROXY", "") or "").strip()
    return {
        "proxy": selected,
        "upstream_proxy": upstream,
        "upstream_proxy_used": _mask_proxy(upstream) or None,
        "proxy_mode": mode,
        "network_route": "proxy_chain" if upstream else "proxy",
        "proxy_used": _mask_proxy(selected),
        "proxy_fallback_reason": None,
    }


def decode_jwt_payload_unverified(token: str) -> dict:
    """chỉ localparse JWT payload，không kiểm nghiệm ký tên 。"""
    token = normalize_token(token)
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except Exception:
        return {}


def token_claims(token: str) -> dict:
    payload = decode_jwt_payload_unverified(token)
    auth = payload.get("https://api.openai.com/auth") or {}
    profile = payload.get("https://api.openai.com/profile") or {}
    exp = payload.get("exp")
    exp_iso = None
    expired = None
    if isinstance(exp, (int, float)):
        exp_iso = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        expired = datetime.now(tz=timezone.utc).timestamp() >= float(exp)
    return {
        "payload": payload,
        "email": profile.get("email"),
        "user_name": profile.get("name"),
        "user_id": auth.get("chatgpt_user_id") or auth.get("user_id"),
        "account_id": auth.get("chatgpt_account_id"),
        "claim_plan_type": auth.get("chatgpt_plan_type"),
        "exp": exp,
        "token_expires_at": exp_iso,
        "token_expired": expired,
    }


def _common_headers(env: BrowserSession, token: str, claims: dict | None = None) -> dict[str, str]:
    """tạo và ChatGPT phiên đăng nhậpfrontendmột khiến góitruy vấnđầu 。"""
    headers = env.get_chatgpt_headers(referer="https://chatgpt.com/")
    # GET 导航后的前端 fetch 不主动设置 content-type。
    headers.pop("content-type", None)
    headers.update({
        "authorization": f"Bearer {normalize_token(token)}",
        "x-openai-target-path": ACCOUNTS_CHECK_PATH,
        "x-openai-target-route": ACCOUNTS_CHECK_PATH,
    })
    account_id = str((claims or {}).get("account_id") or "").strip()
    if account_id:
        headers["chatgpt-account-id"] = account_id
    return headers


def parse_accounts_check(data: dict, *, token: str = "") -> dict:
    """từ accounts/check phản hồinêu lấy góivà Plus dùng thửđiều kiện。"""
    claims = token_claims(token) if token else {}
    claim_account_id = claims.get("account_id")
    accounts = data.get("accounts") if isinstance(data, dict) else None
    if not isinstance(accounts, dict):
        raise ValueError("Phản hồi thiếu object accounts")

    item = None
    account_key = None
    if claim_account_id and isinstance(accounts.get(claim_account_id), dict):
        item = accounts.get(claim_account_id)
        account_key = claim_account_id
    elif isinstance(accounts.get("default"), dict):
        item = accounts.get("default")
        account = item.get("account") or {}
        account_key = account.get("account_id") or "default"
    else:
        for k, v in accounts.items():
            if k != "default" and isinstance(v, dict):
                item = v
                account_key = k
                break
    if not isinstance(item, dict):
        raise ValueError("Không tìm thấy mục tài khoản parse được")

    account = item.get("account") or {}
    entitlement = item.get("entitlement") or {}
    last_sub = item.get("last_active_subscription") or {}
    eligible_promo_campaigns = item.get("eligible_promo_campaigns") or {}
    plus_campaign = eligible_promo_campaigns.get("plus") if isinstance(eligible_promo_campaigns, dict) else None
    plus_meta = (plus_campaign or {}).get("metadata") or {}
    discount = plus_meta.get("discount") or {}
    duration = plus_meta.get("duration") or {}

    plan_type = account.get("plan_type") or claims.get("claim_plan_type") or ""
    subscription_plan = entitlement.get("subscription_plan") or ""
    has_active_subscription = bool(entitlement.get("has_active_subscription"))
    is_free = str(plan_type).lower() == "free" or str(subscription_plan).lower() == "chatgptfreeplan"
    plus_trial_eligible = bool(is_free and plus_campaign)

    # 保留 Free 账号返回的全部促销活动，供前端查看详情；Plus 资格判定仍然
    # 只使用上面的 eligible_promo_campaigns.plus，保持原有语义不变。
    promo_campaigns = {}
    if is_free and isinstance(eligible_promo_campaigns, dict):
        for campaign_key, campaign in eligible_promo_campaigns.items():
            if isinstance(campaign, dict):
                promo_campaigns[str(campaign_key)] = campaign

    offers = ((item.get("eligible_offers") or {}).get("offers") or [])
    eligible_offer_ids = [o.get("id") for o in offers if isinstance(o, dict) and o.get("id")]

    result = {
        "ok": True,
        "checked_at": now_iso(),
        "account_id": account.get("account_id") or account_key or claim_account_id,
        "account_user_role": account.get("account_user_role"),
        "current_plan_type": plan_type,
        "subscription_plan": subscription_plan,
        "has_active_subscription": has_active_subscription,
        "is_active_subscription_gratis": bool(entitlement.get("is_active_subscription_gratis")),
        "expires_at": entitlement.get("expires_at"),
        "renews_at": entitlement.get("renews_at"),
        "cancels_at": entitlement.get("cancels_at"),
        "billing_period": entitlement.get("billing_period"),
        "billing_currency": entitlement.get("billing_currency"),
        "is_delinquent": bool(entitlement.get("is_delinquent")),
        "discount_type": (entitlement.get("discount") or {}).get("discount_type"),
        "discount_amount": (entitlement.get("discount") or {}).get("amount"),
        "discount_duration_num_periods": (entitlement.get("discount") or {}).get("duration_num_periods"),
        "discount_expires_at": (entitlement.get("discount") or {}).get("discount_expires_at"),
        "discount_cancellation_policy": (entitlement.get("discount") or {}).get("cancellation_policy"),
        "discount_promo_campaign_id": (entitlement.get("discount") or {}).get("promo_campaign_id"),
        "last_purchase_origin_platform": last_sub.get("purchase_origin_platform"),
        "last_will_renew": bool(last_sub.get("will_renew")),
        "plus_trial_eligible": plus_trial_eligible,
        "plus_trial_campaign_id": (plus_campaign or {}).get("id"),
        "plus_trial_title": plus_meta.get("title"),
        "plus_trial_summary": plus_meta.get("summary"),
        "plus_trial_discount_percentage": discount.get("percentage"),
        "plus_trial_duration_num_periods": duration.get("num_periods"),
        "plus_trial_duration_period": duration.get("period"),
        "plus_trial_promotion_type_label": plus_meta.get("promotion_type_label"),
        "eligible_promo_campaigns": promo_campaigns,
        "eligible_offer_ids": eligible_offer_ids,
        "features_count": len(item.get("features") or []),
        "can_access_with_session": bool(item.get("can_access_with_session")),
        "raw_account_plan_type": account.get("plan_type"),
    }
    result.update({k: v for k, v in claims.items() if k != "payload" and v is not None})
    return result


def _plan_check_settings(
    timeout: float | None,
    max_attempts: int | None,
    retry_delay: float | None,
) -> tuple[float, int, float]:
    from config import proxy as proxy_cfg

    timeout_value = timeout if timeout is not None else getattr(proxy_cfg, "PLAN_CHECK_TIMEOUT", 15.0)
    attempts_value = max_attempts if max_attempts is not None else getattr(proxy_cfg, "PLAN_CHECK_MAX_ATTEMPTS", 2)
    delay_value = retry_delay if retry_delay is not None else getattr(proxy_cfg, "PLAN_CHECK_RETRY_DELAY", 1.5)
    return (
        max(1.0, min(60.0, float(timeout_value or 15.0))),
        max(1, min(4, int(attempts_value or 1))),
        max(0.0, min(30.0, float(delay_value or 0.0))),
    )


def _retryable_plan_error(http_status: int | None) -> bool:
    if http_status is None:
        return True
    return http_status in {403, 408, 409, 425, 429} or http_status >= 500


def _clear_plan_circuit(env: BrowserSession) -> None:
    """xoá trừ có thể thử lạiphản hồisản sinh localngắt mạch，cùng khigiữ giữ Cookie Jar。"""
    reset = getattr(env, "reset_circuit_breaker", None)
    if callable(reset):
        reset()
    else:
        env.blocked_until = 0.0
        env.blocked_reason = ""


def _warm_plan_session(env: BrowserSession) -> None:
    """trước truy cập hỏi ChatGPT document dựng đứng cùngphiên cạnh duyên Cookie；thất bạikhông chặn ngắt chínhtruy vấn。"""
    try:
        resp = env.get(
            "https://chatgpt.com/",
            headers=env.get_chatgpt_navigate_headers(
                referer="https://chatgpt.com/", user_initiated=False,
            ),
            allow_redirects=True,
        )
        if int(getattr(resp, "status_code", 0) or 0) >= 400:
            logger.info("[Plan] khởi động trước document trả HTTP %s，giữ Cookie phản hồi rồi tiếp tục", resp.status_code)
    except Exception as exc:
        logger.debug("[Plan] khởi động trước document thất bại, tiếp tục truy vấn chính：%s: %s", type(exc).__name__, str(exc)[:160])
    finally:
        _clear_plan_circuit(env)


def _retry_wait_seconds(resp: Any, base_delay: float, attempt: int) -> float:
    try:
        retry_after = (getattr(resp, "headers", {}) or {}).get("retry-after")
        if retry_after is not None:
            return max(0.0, min(30.0, float(retry_after)))
    except (TypeError, ValueError):
        pass
    return max(0.0, min(30.0, base_delay * attempt))


def check_account_plan(
    token: str,
    *,
    proxy: Optional[str] = None,
    timezone_offset_min: str = "-",
    timeout: float | None = None,
    max_attempts: int | None = None,
    retry_delay: float | None = None,
) -> dict:
    token = normalize_token(token)
    if not token:
        return {"ok": False, "checked_at": now_iso(), "error": "token trống"}
    claims = token_claims(token)
    if claims.get("token_expired") is True:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": "AT đã hết hạn/hỏng, hãy kiểm tra sống thủ công để làm mới",
            "needs_live_check": True,
            **{k: v for k, v in claims.items() if k != "payload"},
        }

    try:
        route = resolve_plan_check_route(proxy)
    except Exception as exc:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": f"Lỗi cấu hình mạng truy vấn gói: {exc}",
            **{k: v for k, v in claims.items() if k != "payload"},
        }
    route_meta = {k: v for k, v in route.items() if k not in {"proxy", "upstream_proxy"}}
    try:
        timeout_seconds, attempts, base_delay = _plan_check_settings(timeout, max_attempts, retry_delay)
    except Exception as exc:
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": f"Lỗi cấu hình thử lại truy vấn gói: {exc}",
            "retryable": False,
            **route_meta,
            **{k: v for k, v in claims.items() if k != "payload"},
        }

    last_result: dict | None = None
    identity = str(
        claims.get("email") or claims.get("account_id") or normalize_token(token)[:32]
    ).lower()
    # 任务级随机 seed：同一查询的所有重试统一 device/session/Cookie；不同账号
    # 或下一次查询不会复用旧浏览器身份。
    task_seed = f"plan-check:{identity}:{uuid.uuid4()}"
    env: BrowserSession | None = None
    relay = None
    try:
        # 首次按代理真实出口自动生成语言/时区画像，随后整条查询链固定不漂移。
        effective_proxy, relay = open_plan_check_proxy(
            route, route["proxy"], timeout=timeout_seconds,
        )
        env = BrowserSession(
            proxy=effective_proxy, detect_exit_geo=True, fingerprint_seed=task_seed,
        )
        effective_tz = str(timezone_offset_min or "").strip()
        if not effective_tz or effective_tz == "-":
            effective_tz = str(env.js_timezone_offset_min())
        url = (
            f"https://chatgpt.com{ACCOUNTS_CHECK_PATH}"
            f"?timezone_offset_min={quote(effective_tz)}"
        )
        logger.info(
            "[Plan] đã tạo phiên thống nhất：proxy=%s device_id=%s oai_session_id=%s %s",
            route_meta.get("proxy_used") or route_meta.get("network_route") or "direct",
            str(env.device_id)[:12] + "...",
            str(env.oai_session_id)[:12] + "...",
            env.fingerprint_summary_text(),
        )
        _warm_plan_session(env)

        for attempt in range(1, attempts + 1):
            resp = None
            try:
                resp = env.get(
                    url,
                    headers=_common_headers(env, token, claims),
                    allow_redirects=False,
                    timeout=timeout_seconds,
                )
                response_text = resp.text or ""
                http_status = int(resp.status_code)
                if not (200 <= http_status < 300):
                    is_auth_expired = http_status == 401
                    last_result = {
                        "ok": False,
                        "checked_at": now_iso(),
                        "http_status": http_status,
                        "error": "AT đã hết hạn/hỏng, hãy kiểm tra sống thủ công để làm mới" if is_auth_expired else f"HTTP {http_status}",
                        "response_preview": response_text[:500],
                        "retryable": _retryable_plan_error(http_status),
                        "token_expired": True if is_auth_expired else claims.get("token_expired"),
                        "needs_live_check": True if is_auth_expired else False,
                    }
                else:
                    try:
                        data: Any = resp.json()
                    except Exception:
                        data = json.loads(response_text) if response_text.strip().startswith(("{", "[")) else None
                    if not isinstance(data, dict):
                        last_result = {
                            "ok": False,
                            "checked_at": now_iso(),
                            "http_status": http_status,
                            "error": "Phản hồi không phải object JSON",
                            "response_preview": response_text[:500],
                            "retryable": True,
                        }
                    else:
                        parsed = parse_accounts_check(data, token=token)
                        parsed["http_status"] = http_status
                        parsed["attempt_count"] = attempt
                        parsed["max_attempts"] = attempts
                        parsed["request_timeout"] = timeout_seconds
                        parsed["retryable"] = False
                        parsed["timezone_offset_min"] = effective_tz
                        parsed.update(route_meta)
                        return parsed
            except Exception as exc:
                logger.debug("truy vấn gói thất bại: %s: %s", type(exc).__name__, exc, exc_info=True)
                last_result = {
                    "ok": False,
                    "checked_at": now_iso(),
                    "http_status": int(resp.status_code) if resp is not None and getattr(resp, "status_code", None) else None,
                    "error": f"{type(exc).__name__}: {exc}",
                    "retryable": True,
                }

            last_result = last_result or {"ok": False, "checked_at": now_iso(), "error": "Lỗi không rõ", "retryable": True}
            last_result.update({
                "attempt_count": attempt,
                "max_attempts": attempts,
                "request_timeout": timeout_seconds,
                "timezone_offset_min": effective_tz,
                **route_meta,
                **{k: v for k, v in claims.items() if k != "payload"},
            })
            if not last_result.get("retryable") or attempt >= attempts:
                return last_result

            # 403/429 会打开 BrowserSession 熔断。保留服务端刚下发的 CF Cookie，
            # 只清除本地熔断并在同一会话内退避重试。
            _clear_plan_circuit(env)
            wait_seconds = _retry_wait_seconds(resp, base_delay, attempt)
            logger.warning(
                "truy vấn gói tạm thất bại，lần %s/%s ，giữ giữ session/deviceId/CF Cookie，%.1fs sauthử lại: %s",
                attempt,
                attempts,
                wait_seconds,
                last_result.get("error"),
            )
            if wait_seconds > 0:
                time.sleep(wait_seconds)
    except Exception as exc:
        logger.debug("khởi tạo phiên truy vấn gói thất bại: %s: %s", type(exc).__name__, exc, exc_info=True)
        return {
            "ok": False,
            "checked_at": now_iso(),
            "http_status": None,
            "error": f"{type(exc).__name__}: {exc}",
            "retryable": True,
            "attempt_count": 0,
            "max_attempts": attempts,
            "request_timeout": timeout_seconds,
            **route_meta,
            **{k: v for k, v in claims.items() if k != "payload"},
        }
    finally:
        if env is not None:
            try:
                close_browser_session(env)
            except Exception:
                pass
        if relay is not None:
            relay.close()

    return last_result or {
        "ok": False,
        "checked_at": now_iso(),
        "http_status": None,
        "error": "Truy vấn gói chưa chạy",
        "retryable": False,
        **route_meta,
        **{k: v for k, v in claims.items() if k != "payload"},
    }

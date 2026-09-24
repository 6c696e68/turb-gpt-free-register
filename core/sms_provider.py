# -*- coding: utf-8 -*-
"""
Client nền tảng nhận SMS.

Dùng cho luồng Codex OAuth "session mới" để qua xác minh số điện thoại /phone-verification của OpenAI:
    1. acquire_number()       getNumber lấy một số (trả activation ID + số)
    2. wait_for_sms_code()    poll getStatus đến khi có mã OTP SMS
    3. complete() / cancel()  setStatus đánh dấu hoàn tất (6) / huỷ (8)

Hiện hỗ trợ:
    - GrizzlySMS: API GET văn bản, tài liệu https://api.grizzlysms.com
    - SMSBower: API GET handler_api tương thích, tài liệu https://smsbower.app/cn/api?page=client
    - L: API quản trị JSON cục bộ, tài liệu L_API.md
    - H: API quản trị JSON cục bộ, tài liệu H_API.md

Giá: mỗi lần lấy số và nhận SMS đều tính phí, nên:
    - Sau khi lấy số nếu không nhận SMS, phải cancel(8) để nhả, tránh trừ tiền oan;
    - Có mã rồi thì complete(6) để hoàn tất kích hoạt.
"""
import json
import logging
import threading
import time
from urllib.parse import urljoin

from curl_cffi.requests import Session as CurlSession

# Lưu ý: dùng `from config import codex` chứ không phải `from config.codex import X`,
# Như vậy sau khi WebUI gọi config.reload_all(), module này đọc qua codex.X sẽ là giá trị mới nhất.
from config import codex as _cfg
from config import IMPERSONATE

logger = logging.getLogger(__name__)

# Quy tắc GrizzlySMS: sau khi lấy số trong 2 phút không cho phép hủy (chống lạm dụng lấy số).
# Ở đây để đệm 5 giây, hết thời gian rồi mới gửi setStatus=8.
_MIN_CANCEL_DELAY = 125

# Ghi lại thời gian lấy số của mỗi activation_id, để cancel() quyết định có cần đợi hay không.
# Dùng dict cấp module thay vì đổi giá trị trả về của acquire_number, giữ tương thích ngược.
_ACQUIRED_AT: dict[str, float] = {}


class SmsProviderError(RuntimeError):
    """Lỗi chung của nền tảng nhận SMS."""


class SmsNoNumbersError(SmsProviderError):
    """Tạm không có số (NO_NUMBERS), có thể đổi quốc gia hoặc thử lại sau."""


class SmsNoBalanceError(SmsProviderError):
    """Không đủ số dư (NO_BALANCE), phải nạp tiền, thử lại vô ích — tầng trên phải dừng ngay."""


class SmsCodeTimeout(SmsProviderError):
    """Một số chờ SMS quá hạn (OpenAI không gửi hoặc chưa tới)."""


def _http() -> CurlSession:
    s = CurlSession(impersonate=IMPERSONATE)
    s.timeout = _cfg.SMS_REQUEST_TIMEOUT
    return s


def _provider() -> str:
    return str(getattr(_cfg, "SMS_PROVIDER", "grizzly") or "grizzly").strip().lower()


def _request_grizzly(http: CurlSession, params: dict) -> str:
    """
    Gửi một yêu cầu GrizzlySMS API, trả text phản hồi đã cắt trắng.
    Nhận diện mã lỗi chung và ném exception tương ứng.
    """
    base_params = {"api_key": _cfg.SMS_API_KEY}
    base_params.update(params)
    resp = http.get(_cfg.SMS_API_BASE, params=base_params)
    if resp.status_code != 200:
        raise SmsProviderError(
            f"GrizzlySMS HTTP {resp.status_code}: {(resp.text or '')[:200]}"
        )
    text = (resp.text or "").strip()

    # Mã lỗi chung (mọi action đều có thể trả về)
    if text == "BAD_KEY":
        raise SmsProviderError("API key nền tảng nhận SMS không hợp lệ (BAD_KEY)")
    if text == "NO_BALANCE":
        raise SmsNoBalanceError("Nền tảng nhận SMS không đủ số dư (NO_BALANCE), hãy nạp tiền")
    if text == "NO_NUMBERS":
        raise SmsNoNumbersError("Nền tảng nhận SMS tạm không có số (NO_NUMBERS)")
    if text == "SERVICE_UNAVAILABLE_REGION":
        raise SmsProviderError("Nền tảng nhận SMS bị hạn chế vùng (SERVICE_UNAVAILABLE_REGION), hãy đổi IP")
    if text in ("BAD_ACTION", "BAD_SERVICE", "BAD_STATUS"):
        raise SmsProviderError(f"Tham số yêu cầu nền tảng nhận SMS sai: {text}")
    if text == "NO_ACTIVATION":
        raise SmsProviderError("Activation ID không tồn tại (NO_ACTIVATION)")
    if text.startswith("The service is prohibited"):
        raise SmsProviderError(f"Dịch vụ này bị nền tảng cấm bán: {text}")

    return text


def _request_smsbower(http: CurlSession, params: dict) -> str:
    """Gửi yêu cầu SMSBower handler_api, trả text phản hồi đã cắt trắng."""
    api_key = str(getattr(_cfg, "SMSBOWER_API_KEY", "") or "").strip()
    if not api_key:
        raise SmsProviderError("SMSBower API Key không được để trống")
    base = str(getattr(_cfg, "SMSBOWER_API_BASE", "") or "").strip()
    if not base:
        raise SmsProviderError("SMSBOWER_API_BASE không được để trống")
    resp = http.get(base, params={"api_key": api_key, **params})
    text = (resp.text or "").strip()
    if resp.status_code != 200:
        raise SmsProviderError(f"SMSBower HTTP {resp.status_code}: {text[:200]}")
    if text in ("BAD_KEY", "BAD_ACTION", "BAD_SERVICE", "WRONG_SERVICE", "BAD_STATUS", "NO_ACTIVATION"):
        if text == "BAD_KEY":
            raise SmsProviderError("SMSBower API key không hợp lệ (BAD_KEY)")
        if text in ("BAD_SERVICE", "WRONG_SERVICE"):
            raise SmsProviderError(f"Mã dịch vụ SMSBower không hợp lệ ({text}), OpenAI/ChatGPT hãy điền dr")
        if text == "NO_ACTIVATION":
            raise SmsProviderError("SMSBower activation ID không tồn tại (NO_ACTIVATION)")
        raise SmsProviderError(f"Tham số yêu cầu SMSBower sai: {text}")
    if text in ("NO_NUMBERS", "NO_BALANCE", "NO_MONEY"):
        if text in ("NO_BALANCE", "NO_MONEY"):
            raise SmsNoBalanceError(f"SMSBower không đủ số dư ({text}), hãy nạp tiền")
        raise SmsNoNumbersError("SMSBower tạm không có số (NO_NUMBERS)")
    if text.startswith("The service is prohibited"):
        raise SmsProviderError(f"SMSBower dịch vụ này bị cấm bán: {text}")
    return text


def _smsbower_number_params(service: str | None, country: str | None) -> dict:
    service_code = str(service or _cfg.SMS_SERVICE or "").strip()
    if service_code.lower() in ("openai", "chatgpt"):
        service_code = "dr"
    params = {
        "action": "getNumberV2" if bool(getattr(_cfg, "SMSBOWER_USE_V2", True)) else "getNumber",
        "service": service_code,
        "country": str(country or _cfg.SMS_COUNTRY or "").strip(),
    }
    for key, value in (
        ("maxPrice", getattr(_cfg, "SMS_MAX_PRICE", "")),
        ("minPrice", getattr(_cfg, "SMSBOWER_MIN_PRICE", "")),
        ("providerIds", getattr(_cfg, "SMSBOWER_PROVIDER_IDS", "")),
        ("exceptProviderIds", getattr(_cfg, "SMSBOWER_EXCEPT_PROVIDER_IDS", "")),
        ("phoneException", getattr(_cfg, "SMSBOWER_PHONE_EXCEPTION", "")),
    ):
        value = str(value or "").strip()
        if value:
            params[key] = value
    return params


def _request_smsbower_number(http: CurlSession, params: dict) -> tuple[dict, str]:
    """Lấy số theo thứ tự tương thích, hết tồn kho khi lọc thì nới điều kiện nhà cung cấp."""
    candidates: list[dict] = [dict(params)]
    if params.get("action") == "getNumberV2":
        candidates.append({**params, "action": "getNumber"})
    if params.get("providerIds"):
        without_provider = {key: value for key, value in params.items() if key != "providerIds"}
        candidates.append(without_provider)
        if params.get("action") == "getNumberV2":
            candidates.append({**without_provider, "action": "getNumber"})
    unique = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    for index, candidate in enumerate(unique):
        try:
            return candidate, _request_smsbower(http, candidate)
        except SmsNoNumbersError:
            if index + 1 < len(unique):
                logger.warning("[SMSBower] Lọc lấy số hết tồn kho, nới điều kiện rồi thử lại: action=%s providerIds=%s", candidate.get("action"), candidate.get("providerIds", "-"))
                continue
            raise
        except SmsProviderError as exc:
            if candidate.get("action") == "getNumberV2" and "BAD_ACTION" in str(exc) and index + 1 < len(unique):
                logger.warning("[SMSBower] API hiện tại không hỗ trợ getNumberV2, lùi về API tương thích")
                continue
            raise
    raise SmsProviderError("SMSBower không có phương án lấy số dùng được")


def _l_url(path: str) -> str:
    base = str(getattr(_cfg, "L_API_BASE", "") or "").strip()
    if not base:
        raise SmsProviderError("L_API_BASE không được để trống")
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _l_headers() -> dict:
    token = str(getattr(_cfg, "L_ADMIN_AUTH_CODE", "") or "").strip()
    if not token:
        raise SmsProviderError("L_ADMIN_AUTH_CODE không được để trống")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _post_l_json(http: CurlSession, path: str, payload: dict) -> dict:
    resp = http.post(_l_url(path), headers=_l_headers(), data=json.dumps(payload))
    text = (resp.text or "").strip()
    try:
        data = resp.json()
    except Exception:
        data = {}

    if resp.status_code != 200:
        msg = data.get("error") if isinstance(data, dict) else ""
        raise SmsProviderError(f"L HTTP {resp.status_code}: {(msg or text)[:200]}")
    if isinstance(data, dict) and data.get("error"):
        error = str(data.get("error") or "")
        raw = str(data.get("raw") or "")
        combined = f"{error} {raw}".strip()
        if "NO_BALANCE" in combined or "余额不足" in combined:
            raise SmsNoBalanceError(f"L không đủ số dư: {combined}")
        if "NO_NUMBERS" in combined or "暂无号码" in combined:
            raise SmsNoNumbersError(f"L tạm không có số: {combined}")
        raise SmsProviderError(f"Yêu cầu L thất bại: {combined}")
    if not isinstance(data, dict):
        raise SmsProviderError(f"Phản hồi L không phải object JSON: {text[:200]}")
    return data


def _h_url(path: str) -> str:
    base = str(getattr(_cfg, "H_API_BASE", "") or "").strip()
    if not base:
        raise SmsProviderError("H_API_BASE không được để trống")
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _h_headers() -> dict:
    token = str(getattr(_cfg, "H_ADMIN_AUTH_CODE", "") or "").strip()
    if not token:
        raise SmsProviderError("H_ADMIN_AUTH_CODE không được để trống")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _post_h_json(http: CurlSession, path: str, payload: dict) -> dict:
    resp = http.post(_h_url(path), headers=_h_headers(), data=json.dumps(payload))
    text = (resp.text or "").strip()
    try:
        data = resp.json()
    except Exception:
        data = {}

    if resp.status_code != 200:
        msg = data.get("error") if isinstance(data, dict) else ""
        raise SmsProviderError(f"H HTTP {resp.status_code}: {(msg or text)[:200]}")
    if isinstance(data, dict) and data.get("error"):
        error = str(data.get("error") or "")
        raw = str(data.get("raw") or "")
        combined = f"{error} {raw}".strip()
        if "NO_BALANCE" in combined or "余额不足" in combined:
            raise SmsNoBalanceError(f"H không đủ số dư: {combined}")
        if "NO_NUMBERS" in combined or "暂无号码" in combined:
            raise SmsNoNumbersError(f"H tạm không có số: {combined}")
        raise SmsProviderError(f"Yêu cầu H thất bại: {combined}")
    if not isinstance(data, dict):
        raise SmsProviderError(f"Phản hồi H không phải object JSON: {text[:200]}")
    return data


def _release_h_number(activation_id: str, http: CurlSession | None = None) -> dict:
    """Gọi H_API /api/admin/h/release để nhả một số."""
    activation_id = str(activation_id or "").strip()
    if not activation_id:
        raise SmsProviderError("H release thiếu id")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_h_json(http, "/api/admin/h/release", {"id": activation_id})
        failed = data.get("failed") if isinstance(data, dict) else None
        if isinstance(failed, list) and failed:
            detail = json.dumps(failed, ensure_ascii=False)[:300]
            raise SmsProviderError(f"H release thất bại id={activation_id}: {detail}")
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        logger.info(f"[SMS:H] Đã nhả số id={activation_id}, released={released}")
        _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def release_h_numbers(ids: list[str], http: CurlSession | None = None) -> dict:
    """Nhả số H hàng loạt."""
    ids = [str(x or "").strip() for x in (ids or []) if str(x or "").strip()]
    if not ids:
        raise SmsProviderError("H release thiếu ids")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_h_json(http, "/api/admin/h/release", {"ids": ids})
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        failed = data.get("failed") if isinstance(data, dict) else []
        logger.info(f"[SMS:H] Nhả số hàng loạt xong released={released}, failed={len(failed) if isinstance(failed, list) else 0}")
        for activation_id in ids:
            _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def _release_l_number(activation_id: str, http: CurlSession | None = None) -> dict:
    """Gọi L_API /api/admin/l/release để nhả một số."""
    activation_id = str(activation_id or "").strip()
    if not activation_id:
        raise SmsProviderError("L release thiếu id")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_l_json(http, "/api/admin/l/release", {"id": activation_id})
        failed = data.get("failed") if isinstance(data, dict) else None
        if isinstance(failed, list) and failed:
            # API cho phép thất bại một phần. Khi giải phóng đơn lẻ, failed không rỗng về cơ bản nghĩa là id này giải phóng thất bại.
            detail = json.dumps(failed, ensure_ascii=False)[:300]
            raise SmsProviderError(f"L release thất bại id={activation_id}: {detail}")
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        logger.info(f"[SMS:L] Đã nhả số id={activation_id}, released={released}")
        _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def release_l_numbers(ids: list[str], http: CurlSession | None = None) -> dict:
    """Nhả số L hàng loạt, để tool/batch sau tái sử dụng."""
    ids = [str(x or "").strip() for x in (ids or []) if str(x or "").strip()]
    if not ids:
        raise SmsProviderError("L release thiếu ids")
    own_http = http is None
    http = http or _http()
    try:
        data = _post_l_json(http, "/api/admin/l/release", {"ids": ids})
        released = data.get("released", data.get("updated", 0)) if isinstance(data, dict) else 0
        failed = data.get("failed") if isinstance(data, dict) else []
        logger.info(f"[SMS:L] Nhả số hàng loạt xong released={released}, failed={len(failed) if isinstance(failed, list) else 0}")
        for activation_id in ids:
            _ACQUIRED_AT.pop(activation_id, None)
        return data
    finally:
        if own_http:
            http.close()


def _normalize_phone_digits(value: str) -> str:
    """Chuẩn hoá mảnh số do nền tảng trả/cấu hình thành chữ số thuần, tránh E.164 sai kiểu +-849..."""
    return "".join(ch for ch in str(value or "").strip() if ch.isdigit())


def _normalize_l_phone(phone: str) -> str:
    phone = _normalize_phone_digits(phone)
    prefix = _normalize_phone_digits(getattr(_cfg, "L_PHONE_PREFIX", ""))
    if prefix and phone and not phone.startswith(prefix):
        return f"{prefix}{phone}"
    return phone


def _normalize_h_phone(phone: str) -> str:
    phone = _normalize_phone_digits(phone)
    prefix = _normalize_phone_digits(getattr(_cfg, "H_PHONE_PREFIX", ""))
    if prefix and phone and not phone.startswith(prefix):
        return f"{prefix}{phone}"
    return phone


def _h_phone_acquire_mode() -> str:
    """
    Chế độ lấy số H:
      - reusable/reuse/prefer_reuse: ưu tiên tái sử dụng, gọi /api/admin/h/take-reusable-phone
      - new/fresh/always_new: mỗi lần lấy số mới, gọi /api/admin/h/take-phone
    """
    raw = str(getattr(_cfg, "H_PHONE_ACQUIRE_MODE", "reusable") or "reusable").strip().lower()
    if raw in ("new", "fresh", "always_new", "take_phone", "take-phone", "每次取新号", "新号"):
        return "new"
    return "reusable"


# ============================================================
# Lấy số
# ============================================================

def acquire_number(
    http: CurlSession | None = None,
    service: str | None = None,
    country: str | None = None,
) -> tuple[str, str]:
    """
    Lấy một số điện thoại (getNumber).

    Returns:
        (activation_id, phone_number) — phone_number không có tiền tố + (ví dụ 16195366483)

    Raises:
        SmsNoNumbersError / SmsNoBalanceError / SmsProviderError
    """
    own_http = http is None
    http = http or _http()
    try:
        if _provider() == "smsbower":
            params, text = _request_smsbower_number(http, _smsbower_number_params(service, country))
            if params["action"] == "getNumberV2":
                try:
                    data = json.loads(text)
                except Exception:
                    data = None
                if isinstance(data, dict):
                    activation_id = str(data.get("activationId") or data.get("id") or "").strip()
                    phone = str(data.get("phoneNumber") or data.get("phone") or "").strip()
                    if activation_id and phone:
                        _ACQUIRED_AT[activation_id] = time.time()
                        return activation_id, phone
                raise SmsProviderError(f"SMSBower getNumberV2 phản hồi sai định dạng: {text[:200]}")
            if not text.startswith("ACCESS_NUMBER:"):
                raise SmsProviderError(f"SMSBower getNumber phản hồi không mong đợi: {text[:200]}")
            parts = text.split(":", 2)
            if len(parts) < 3:
                raise SmsProviderError(f"SMSBower getNumber phản hồi sai định dạng: {text[:200]}")
            activation_id, phone = parts[1].strip(), parts[2].strip()
            _ACQUIRED_AT[activation_id] = time.time()
            return activation_id, phone

        if _provider() == "l":
            payload = {
                "service": service or _cfg.SMS_SERVICE,
                "country": country or _cfg.SMS_COUNTRY,
            }
            if _cfg.SMS_MAX_PRICE:
                payload["maxPrice"] = _cfg.SMS_MAX_PRICE

            data = _post_l_json(http, "/api/admin/l/take-phone", payload)
            item = data.get("item") or {}
            activation_id = str(item.get("id") or "").strip()
            raw_phone = str(item.get("phone") or "")
            raw_prefix = str(getattr(_cfg, "L_PHONE_PREFIX", "") or "")
            phone = _normalize_l_phone(raw_phone)
            if raw_phone.strip() != phone or raw_prefix.strip():
                logger.info(
                    f"[SMS:L] Chuẩn hoá số: raw_phone={raw_phone!r}, "
                    f"prefix={raw_prefix!r}, normalized=+{phone}"
                )
            if not activation_id or not phone:
                raise SmsProviderError(f"L take-phone phản hồi thiếu item.id/item.phone: {str(data)[:200]}")
            _ACQUIRED_AT[activation_id] = time.time()
            logger.info(f"[SMS:L] Lấy số thành công: id={activation_id}, phone=+{phone}")
            return activation_id, phone

        if _provider() == "h":
            # H_API dùng projectId + country; thống nhất tái sử dụng SMS_SERVICE / SMS_COUNTRY,
            # Tránh cấu hình "dịch vụ/quốc gia" trùng lặp giữa các nền tảng nhận mã.
            project_id = str(service or _cfg.SMS_SERVICE).strip()
            h_country = str(country or _cfg.SMS_COUNTRY).strip()
            if not project_id:
                raise SmsProviderError("H projectId không được để trống: hãy điền SMS_SERVICE")
            if not h_country:
                raise SmsProviderError("H country không được để trống: hãy điền SMS_COUNTRY")
            payload = {
                "projectId": project_id,
                "country": h_country,
            }
            mode = _h_phone_acquire_mode()
            api_path = "/api/admin/h/take-phone" if mode == "new" else "/api/admin/h/take-reusable-phone"
            data = _post_h_json(http, api_path, payload)
            item = data.get("item") or {}
            activation_id = str(item.get("id") or "").strip()
            raw_phone = str(item.get("phone") or "")
            raw_prefix = str(getattr(_cfg, "H_PHONE_PREFIX", "") or "")
            phone = _normalize_h_phone(raw_phone)
            if raw_phone.strip() != phone or raw_prefix.strip():
                logger.info(
                    f"[SMS:H] Chuẩn hoá số: raw_phone={raw_phone!r}, "
                    f"prefix={raw_prefix!r}, normalized=+{phone}"
                )
            if not activation_id or not phone:
                raise SmsProviderError(f"H {api_path.rsplit('/', 1)[-1]} phản hồi thiếu item.id/item.phone: {str(data)[:200]}")
            _ACQUIRED_AT[activation_id] = time.time()
            logger.info(
                f"[SMS:H] Lấy số thành công: mode={mode}, api={api_path}, id={activation_id}, phone=+{phone}, "
                f"reused={bool(data.get('reused'))}, duplicate={bool(data.get('duplicate'))}"
            )
            return activation_id, phone

        params = {
            "action": "getNumber",
            "service": service or _cfg.SMS_SERVICE,
            "country": country or _cfg.SMS_COUNTRY,
        }
        if _cfg.SMS_MAX_PRICE:
            params["maxPrice"] = _cfg.SMS_MAX_PRICE

        text = _request_grizzly(http, params)
        # Định dạng thành công: ACCESS_NUMBER:ID kích hoạt:số
        if not text.startswith("ACCESS_NUMBER:"):
            raise SmsProviderError(f"getNumber phản hồi không mong đợi: {text[:200]}")
        parts = text.split(":")
        if len(parts) < 3:
            raise SmsProviderError(f"getNumber phản hồi sai định dạng: {text[:200]}")
        activation_id = parts[1].strip()
        phone = parts[2].strip()
        _ACQUIRED_AT[activation_id] = time.time()
        logger.info(f"[SMS] Lấy số thành công: activation_id={activation_id}, phone=+{phone}")
        return activation_id, phone
    finally:
        if own_http:
            http.close()


# ============================================================
# Lấy mã xác minh SMS
# ============================================================

def wait_for_sms_code(
    activation_id: str,
    http: CurlSession | None = None,
    max_wait: int | None = None,
    poll_interval: int | None = None,
) -> str:
    """
    Poll getStatus đến khi có mã OTP SMS.

    Returns:
        chuỗi mã OTP

    Raises:
        SmsCodeTimeout — quá hạn chưa nhận (tầng trên có thể đổi số thử lại)
        SmsProviderError — kích hoạt bị huỷ, v.v.
    """
    own_http = http is None
    http = http or _http()
    deadline = time.time() + (max_wait or _cfg.SMS_CODE_WAIT)
    interval = poll_interval or _cfg.SMS_POLL_INTERVAL
    try:
        provider = _provider()
        total_wait = max_wait or _cfg.SMS_CODE_WAIT
        logger.info(f"[SMS] Chờ mã OTP SMS activation_id={activation_id}, tối đa {total_wait}s...")
        round_no = 0
        while time.time() < deadline:
            try:
                from core.registration_service import check_stop_requested
                check_stop_requested()
            except ImportError:
                pass
            round_no += 1
            elapsed = max(0, int(total_wait - max(0, deadline - time.time())))
            remaining_before = max(0, int(deadline - time.time()))
            logger.info(
                f"[SMS] Vòng {round_no} vòng lấy mã OTP activation_id={activation_id}，"
                f"đã chờ {elapsed}s, còn khoảng {remaining_before}s"
            )
            if provider == "l":
                data = _post_l_json(http, "/api/admin/l/fetch-code", {"id": activation_id})
                code = str(data.get("code") or "").strip()
                raw = str(data.get("raw") or "").strip()
                status = str((data.get("item") or {}).get("status") or "").strip()
                if code:
                    logger.info(f"[SMS:L] Vòng {round_no} vòng nhận mã OTP: {code}")
                    return code
                remaining = max(0, int(deadline - time.time()))
                logger.info(
                    f"[SMS:L] Vòng {round_no} vòng chưa nhận mã OTP, trạng thái={status or raw or 'WAIT'}，"
                    f"{interval}s nữa thử lại (còn {remaining}s）"
                )
                time.sleep(interval)
                continue

            if provider == "h":
                data = _post_h_json(http, "/api/admin/h/fetch-code", {"id": activation_id})
                code = str(data.get("code") or "").strip()
                raw = str(data.get("raw") or "").strip()
                status = str((data.get("item") or {}).get("status") or "").strip()
                if code:
                    logger.info(f"[SMS:H] Vòng {round_no} vòng nhận mã OTP: {code}")
                    return code
                remaining = max(0, int(deadline - time.time()))
                logger.info(
                    f"[SMS:H] Vòng {round_no} vòng chưa nhận mã OTP, trạng thái={status or raw or 'WAIT'}，"
                    f"{interval}s nữa thử lại (còn {remaining}s）"
                )
                time.sleep(interval)
                continue

            if provider == "smsbower":
                text = _request_smsbower(http, {"action": "getStatus", "id": activation_id})
                if text.startswith("STATUS_OK:"):
                    return text.split(":", 1)[1].strip().strip("'")
                if text == "STATUS_CANCEL":
                    raise SmsProviderError("SMSBower kích hoạt đã bị huỷ (STATUS_CANCEL)")
                time.sleep(interval)
                continue

            text = _request_grizzly(http, {"action": "getStatus", "id": activation_id})

            if text.startswith("STATUS_OK:"):
                code = text.split(":", 1)[1].strip()
                logger.info(f"[SMS] Vòng {round_no} vòng nhận mã OTP: {code}")
                return code
            if text == "STATUS_CANCEL":
                raise SmsProviderError("Kích hoạt đã bị huỷ (STATUS_CANCEL)")
            # STATUS_WAIT_CODE / STATUS_WAIT_RETRY:* / STATUS_WAIT_RESEND → tiếp tục chờ
            remaining = max(0, int(deadline - time.time()))
            logger.info(f"[SMS] Vòng {round_no} vòng chưa nhận mã OTP, trạng thái={text}，{interval}s nữa thử lại (còn {remaining}s）")
            time.sleep(interval)

        raise SmsCodeTimeout(f"Chờ SMS quá hạn (>{total_wait}s），activation_id={activation_id}")
    finally:
        if own_http:
            http.close()


# ============================================================
# Đổi trạng thái
# ============================================================

def set_status(activation_id: str, status: int, http: CurlSession | None = None) -> str:
    """
    Đặt trạng thái kích hoạt (setStatus).
        1 = số đã sẵn sàng (SMS đã gửi)
        3 = chờ SMS tiếp theo (gửi lại)
        6 = hoàn tất kích hoạt
        8 = huỷ kích hoạt
    """
    own_http = http is None
    http = http or _http()
    try:
        if _provider() == "l":
            logger.debug(f"[SMS:L] Bỏ qua đặt trạng thái id={activation_id}, status={status}")
            return "OK"
        if _provider() == "smsbower":
            if int(status) == 1:
                return "OK"
            return _request_smsbower(http, {"action": "setStatus", "status": str(status), "id": activation_id})
        return _request_grizzly(http, {"action": "setStatus", "status": str(status), "id": activation_id})
    finally:
        if own_http:
            http.close()


def complete(activation_id: str, http: CurlSession | None = None) -> None:
    """Đánh dấu kích hoạt hoàn tất (status=6). Thất bại chỉ cảnh báo, không ném, để khỏi ảnh hưởng luồng chính."""
    if _provider() == "l":
        logger.info(f"[SMS:L] Đã hoàn tất id={activation_id}")
        _ACQUIRED_AT.pop(activation_id, None)
        return
    if _provider() == "h":
        # Sau khi H fetch-code thành công, backend sẽ tự động lấy lại theo chiến lược nhận mã nhiều lần; ở đây không release.
        logger.info(f"[SMS:H] Đã hoàn tất id={activation_id}")
        _ACQUIRED_AT.pop(activation_id, None)
        return
    if _provider() == "smsbower":
        try:
            set_status(activation_id, 6, http=http)
        except Exception as exc:
            logger.warning(f"[SMSBower] Đánh dấu hoàn tất thất bại (không ảnh hưởng kết quả): {exc}")
        finally:
            _ACQUIRED_AT.pop(activation_id, None)
        return
    try:
        set_status(activation_id, 6, http=http)
        logger.info(f"[SMS] Đã đánh dấu hoàn tất activation_id={activation_id}")
        _ACQUIRED_AT.pop(activation_id, None)
    except Exception as exc:
        logger.warning(f"[SMS] Đánh dấu hoàn tất thất bại (không ảnh hưởng kết quả): {exc}")


def _do_cancel_sync(activation_id: str, http_factory) -> None:
    """Logic huỷ đồng bộ thật: chờ đủ hạn 2 phút → gửi yêu cầu → thất bại thì thử lại một lần."""
    acquired_at = _ACQUIRED_AT.get(activation_id)
    if acquired_at is not None:
        elapsed = time.time() - acquired_at
        if elapsed < _MIN_CANCEL_DELAY:
            wait = _MIN_CANCEL_DELAY - elapsed
            logger.info(
                f"[SMS] Huỷ đang chờ hạn 2 phút GrizzlySMS: activation_id={activation_id}，"
                f"còn phải chờ {wait:.0f}s..."
            )
            time.sleep(wait)

    # Thread nền không thể tái sử dụng http session bên ngoài (curl_cffi không an toàn luồng), tự tạo một cái
    http = http_factory()
    try:
        for attempt in range(1, 3):
            try:
                set_status(activation_id, 8, http=http)
                logger.info(f"[SMS] Đã huỷ activation_id={activation_id}")
                _ACQUIRED_AT.pop(activation_id, None)
                return
            except Exception as exc:
                if attempt == 1:
                    logger.warning(f"[SMS] Huỷ thất bại ({exc}), thử lại sau 5s...")
                    time.sleep(5)
                else:
                    logger.warning(
                        f"[SMS] Huỷ cuối cùng thất bại (không ảnh hưởng kết quả, cần huỷ tay trên nền tảng): activation_id={activation_id}, {exc}"
                    )
    finally:
        try:
            http.close()
        except Exception:
            pass


def cancel(activation_id: str, http: CurlSession | None = None, background: bool = True) -> None:
    """
    Huỷ kích hoạt (status=8), nhả số để tránh trừ phí oan.

    Quy tắc GrizzlySMS: khoảng 2 phút sau khi lấy số không được huỷ. Hàm này mặc định background=True,
    đưa "chờ 2 phút + huỷ" vào thread nền, luồng chính trả ngay để đi tiếp (ví dụ đổi số khác),
    tránh bị chặn 2 phút này.

    background=False thì chờ đủ thời gian rồi mới trả (dùng khi cần xác nhận huỷ xong).

    Thất bại chỉ cảnh báo, không ném, không ảnh hưởng luồng chính.
    """
    if _provider() == "l":
        try:
            _release_l_number(activation_id, http=http)
        except Exception as exc:
            logger.warning(f"[SMS:L] Nhả số thất bại (không ảnh hưởng luồng chính): id={activation_id}, {type(exc).__name__}: {exc}")
            _ACQUIRED_AT.pop(activation_id, None)
        return
    if _provider() == "h":
        try:
            _release_h_number(activation_id, http=http)
        except Exception as exc:
            logger.warning(f"[SMS:H] Nhả số thất bại (không ảnh hưởng luồng chính): id={activation_id}, {type(exc).__name__}: {exc}")
            _ACQUIRED_AT.pop(activation_id, None)
        return
    if _provider() == "smsbower":
        try:
            set_status(activation_id, 8, http=http)
        except Exception as exc:
            logger.warning(f"[SMSBower] Nhả số thất bại (không ảnh hưởng luồng chính): {exc}")
        finally:
            _ACQUIRED_AT.pop(activation_id, None)
        return

    if not background:
        _do_cancel_sync(activation_id, _http)
        return

    t = threading.Thread(
        target=_do_cancel_sync,
        args=(activation_id, _http),
        name=f"sms-cancel-{activation_id}",
        daemon=True,
    )
    t.start()
    logger.debug(f"[SMS] Đã đẩy task huỷ ra nền: activation_id={activation_id}")

# -*- coding: utf-8 -*-
"""
Lớp adapter Sentinel Runner
Gọi sentinel-runner.js ở thư mục gốc dự án qua subprocess,
để Node.js chạy thật sdk.js trong sandbox vm, tạo sentinel-token vượt qua kiểm tra.

Nguyên lý hoạt động:
1. Phía Python gọi trước sentinel.openai.com/backend-api/sentinel/req lấy challenge JSON
2. Ghi challenge vào file tạm
3. Gọi node sentinel-runner.js --challenge-file <file tạm> ...
4. Bắt stdout chính là value của openai-sentinel-token
"""
import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from config import (
    USER_AGENT,
    CHROME_MAJOR,
    CHROME_FULL_VERSION,
    SEC_CH_UA,
    SEC_CH_UA_PLATFORM,
    SEC_CH_UA_FULL_VERSION_LIST,
    SEC_CH_UA_PLATFORM_VERSION,
    SEC_CH_UA_ARCH,
    SEC_CH_UA_BITNESS,
    SEC_CH_UA_MODEL,
    TIMEZONE_IANA,
    TIMEZONE_NAME,
    TIMEZONE_OFFSET_MINUTES,
    NAVIGATOR_LANGUAGE,
    NAVIGATOR_LANGUAGES,
    SCREEN_WIDTH,
    SCREEN_HEIGHT,
    HARDWARE_CONCURRENCY,
    JS_HEAP_SIZE_LIMIT,
    DEVICE_MEMORY,
    SENTINEL_SV,
    OPENAI_BUILD_ID,
)

logger = logging.getLogger(__name__)

# Thư mục gốc dự án (cấp trên của core)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Tài nguyên Node đặt trong thư mục con sentinel/ ở gốc dự án
_SENTINEL_DIR = _PROJECT_ROOT / "sentinel"
_RUNNER_PATH = _SENTINEL_DIR / "sentinel-runner.js"
_SDK_PATH = _SENTINEL_DIR / "sdk.js"

# page-url tương ứng từng flow (khớp trang thực tế của trình duyệt, ảnh hưởng tạo fingerprint sdk.js)
_FLOW_PAGE_URL = {
    "username_password_create": "https://auth.openai.com/create-account/password",
    "email_otp_validate": "https://auth.openai.com/email-verification",
    "authorize_continue": "https://auth.openai.com/email-verification",
    "oauth_create_account": "https://auth.openai.com/about-you",
}

# Thời gian chờ tiến trình con Node (giây). Bên trong sdk.js có thể cần làm PoW, để dư một chút
_RUNNER_TIMEOUT = 60


def _resolve_node_executable() -> str:
    """
    Phân giải tên tệp thực thi Node. Mặc định trên Windows là node.exe, trên hệ giống Unix là node.
    Cho phép ghi đè qua biến môi trường NODE_EXECUTABLE.
    """
    override = os.environ.get("NODE_EXECUTABLE")
    if override:
        return override
    return "node.exe" if sys.platform.startswith("win") else "node"


def _ensure_runner_environment() -> None:
    """Kiểm tra bắt buộc trước khi khởi động: runner.js / sdk.js phải tồn tại."""
    if not _RUNNER_PATH.exists():
        raise FileNotFoundError(f"không tìm thấy sentinel-runner.js: {_RUNNER_PATH}")
    if not _SDK_PATH.exists():
        raise FileNotFoundError(f"không tìm thấy sdk.js: {_SDK_PATH}")


def generate_sentinel_token(
    challenge: dict,
    flow: str,
    device_id: str,
    user_agent: str | None = None,
    page_url: str | None = None,
    browser_profile: dict | None = None,
    sentinel_sid: str | None = None,
    react_listening_key: str | None = None,
    react_container_key: str | None = None,
    react_resources_key: str | None = None,
    cookie: str | None = None,
) -> str:
    """
    Đưa challenge trả về từ sentinel.openai.com vào sdk.js để tạo chuỗi sentinel-token cuối cùng.

    Args:
        challenge: JSON đầy đủ trả về từ sentinel/req (gồm các trường token / proofofwork / turnstile / so)
        flow: định danh luồng, ví dụ username_password_create / authorize_continue / oauth_create_account
        device_id: oai-did, phải cùng giá trị với BrowserSession phía Python
        user_agent: phải khớp hoàn toàn với UA request phía Python; mặc định đọc config.USER_AGENT
        page_url: URL trang hiện tại (ảnh hưởng fingerprint referer / location); mặc định suy ra theo flow

    Returns:
        giá trị chuỗi đầy đủ của header openai-sentinel-token (stdout của runner trả về nguyên bản, đã là chuỗi JSON)

    Raises:
        FileNotFoundError: thiếu runner.js hoặc sdk.js
        RuntimeError: tiến trình con Node lỗi hoặc trả mã thoát khác 0
    """
    _ensure_runner_environment()

    if not flow:
        raise ValueError("flow không được trống")
    if not device_id:
        raise ValueError("device_id không được trống")

    profile = browser_profile or {}
    browser_family = str(profile.get("browser_family") or "chrome")
    request_idle_callback = int((profile.get("window_feature_flags") or {}).get("requestIdleCallback", 0))
    ua = user_agent or str(profile.get("user_agent") or USER_AGENT)
    screen_width = int(profile.get("screen_width", SCREEN_WIDTH))
    screen_height = int(profile.get("screen_height", SCREEN_HEIGHT))
    hardware_concurrency = int(profile.get("hardware_concurrency", HARDWARE_CONCURRENCY))
    js_heap_size_limit = int(profile.get("js_heap_size_limit", JS_HEAP_SIZE_LIMIT))
    device_memory = int(profile.get("device_memory", DEVICE_MEMORY))
    device_pixel_ratio = float(profile.get("device_pixel_ratio", 2))
    screen_avail_width = int(profile.get("screen_avail_width", screen_width))
    screen_avail_height = int(profile.get("screen_avail_height", max(0, screen_height - 25)))
    outer_width = int(profile.get("outer_width", screen_avail_width))
    outer_height = int(profile.get("outer_height", screen_avail_height))
    inner_width = int(profile.get("inner_width", profile.get("viewport_width", outer_width)))
    inner_height = int(profile.get(
        "inner_height", profile.get("viewport_height", max(0, outer_height - 87))
    ))
    color_depth = int(profile.get("color_depth", 24))
    navigator_language = str(profile.get("navigator_language", NAVIGATOR_LANGUAGE))
    navigator_languages = list(profile.get("navigator_languages", NAVIGATOR_LANGUAGES))
    chrome_major = str(profile.get("chrome_major", CHROME_MAJOR))
    chrome_full_version = str(profile.get("chrome_full_version", CHROME_FULL_VERSION))
    sec_ch_ua = str(profile.get("sec_ch_ua", SEC_CH_UA))
    sec_ch_ua_platform = str(profile.get("sec_ch_ua_platform", SEC_CH_UA_PLATFORM))
    navigator_platform = str(profile.get("navigator_platform", "MacIntel"))
    navigator_vendor = str(profile.get("navigator_vendor", "Google Inc."))
    user_agent_data_platform = str(profile.get("user_agent_data_platform", sec_ch_ua_platform.strip('\"') or "macOS"))
    sec_ch_ua_full_version_list = str(profile.get("sec_ch_ua_full_version_list", SEC_CH_UA_FULL_VERSION_LIST))
    sec_ch_ua_platform_version = str(profile.get("sec_ch_ua_platform_version", SEC_CH_UA_PLATFORM_VERSION))
    sec_ch_ua_arch = str(profile.get("sec_ch_ua_arch", SEC_CH_UA_ARCH))
    sec_ch_ua_bitness = str(profile.get("sec_ch_ua_bitness", SEC_CH_UA_BITNESS))
    sec_ch_ua_model = str(profile.get("sec_ch_ua_model", SEC_CH_UA_MODEL))
    build_id = str(profile.get("build_id", OPENAI_BUILD_ID))
    # documentElement của Sentinel token trên trang Auth thường không có data-build;
    # Chỉ p của prepare/finalize trên trang ChatGPT mới mang build frontend.
    runner_build_id = "" if page_url is None and flow in {
        "email_otp_validate", "authorize_continue", "oauth_create_account", "username_password_create"
    } else build_id
    timezone_iana = str(profile.get("timezone_iana", TIMEZONE_IANA))
    timezone_name = str(profile.get("timezone_name", TIMEZONE_NAME))
    timezone_offset_minutes = int(profile.get("timezone_offset_minutes", TIMEZONE_OFFSET_MINUTES))
    runner_cookie = cookie or f"oai-did={device_id}"

    page = page_url or _FLOW_PAGE_URL.get(
        flow, "https://auth.openai.com/create-account/password"
    )

    # dx được làm rối bằng p lúc gửi sentinel/req. proof này chỉ truyền cục bộ cho runner,
    # Không nên lộ cho SDK như trường bổ sung của challenge.
    challenge_proof = str(challenge.get("_request_p") or "") if isinstance(challenge, dict) else ""
    challenge_payload = (
        {k: v for k, v in challenge.items() if k != "_request_p"}
        if isinstance(challenge, dict) else challenge
    )

    # Ghi challenge vào file tạm, tránh vấn đề độ dài dòng lệnh / escape
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        prefix=f"sentinel-challenge-{flow}-",
        delete=False,
        encoding="utf-8",
    )
    try:
        json.dump(challenge_payload, tmp, ensure_ascii=False)
        tmp.flush()
        tmp.close()

        cmd = [
            _resolve_node_executable(),
            str(_RUNNER_PATH),
            "--challenge-file", tmp.name,
            "--flow", flow,
            "--device-id", device_id,
            "--sentinel-sid", sentinel_sid or "",
            "--challenge-proof", challenge_proof,
            "--react-listening-key", react_listening_key or "",
            "--react-container-key", react_container_key or str(profile.get("react_container_key") or ""),
            "--react-resources-key", react_resources_key or str(profile.get("react_resources_key") or ""),
            "--page-url", page,
            "--user-agent", ua,
            "--browser-family", browser_family,
            "--navigator-platform", navigator_platform,
            "--navigator-vendor", navigator_vendor,
            "--user-agent-data-platform", user_agent_data_platform,
            "--request-idle-callback", "1" if request_idle_callback else "0",
            "--sdk", str(_SDK_PATH),
            # p[5] ban đầu của yêu cầu challenge đều đến từ SDK đã version hóa; header gửi cuối cùng thì do
            # Auth page wrapper do SDK tạo: trang mật khẩu/hồ sơ là backend-api, trang OTP là địa chỉ có phiên bản.
            "--script-src", (
                f"https://sentinel.openai.com/sentinel/{SENTINEL_SV}/sdk.js"
                if flow == "email_otp_validate"
                else "https://sentinel.openai.com/backend-api/sentinel/sdk.js"
            ),
            "--build-id", runner_build_id,
            # Giữ nhất quán với giá trị mặc định fingerprint trong config.browser / core.sentinel.py
            "--width", str(screen_width),
            "--height", str(screen_height),
            "--avail-width", str(screen_avail_width),
            "--avail-height", str(screen_avail_height),
            "--outer-width", str(outer_width),
            "--outer-height", str(outer_height),
            "--inner-width", str(inner_width),
            "--inner-height", str(inner_height),
            "--color-depth", str(color_depth),
            "--cores", str(hardware_concurrency),
            "--language", navigator_language,
            "--languages", ",".join(navigator_languages),
            "--time-zone", timezone_iana,
            "--timezone-name", timezone_name,
            "--timezone-offset-minutes", str(timezone_offset_minutes),
            "--js-heap-size-limit", str(js_heap_size_limit),
            "--device-memory", str(device_memory),
            "--device-pixel-ratio", str(device_pixel_ratio),
            "--chrome-major", chrome_major,
            "--chrome-full-version", chrome_full_version,
            "--sec-ch-ua", sec_ch_ua,
            "--sec-ch-ua-platform", sec_ch_ua_platform,
            "--sec-ch-ua-full-version-list", sec_ch_ua_full_version_list,
            "--sec-ch-ua-platform-version", sec_ch_ua_platform_version,
            "--sec-ch-ua-arch", sec_ch_ua_arch,
            "--sec-ch-ua-bitness", sec_ch_ua_bitness,
            "--sec-ch-ua-model", sec_ch_ua_model,
            "--webgl-vendor", str(profile.get("webgl_vendor") or ""),
            "--webgl-renderer", str(profile.get("webgl_renderer") or ""),
            "--cookie", runner_cookie,
        ]

        logger.info(f"[SentinelRunner] gọi Node tạo token, flow={flow}")
        logger.debug(f"[SentinelRunner] lệnh: {' '.join(cmd)}")

        # Quan trọng: tắt tự động phát hiện sentinel.config.json (tránh nhiễu cấu hình bên ngoài)
        env = os.environ.copy()
        env.pop("SENTINEL_CONFIG", None)
        env["SENTINEL_CONFIG"] = "__none__"  # Cố ý trỏ file không tồn tại, bỏ qua list fallback
        env["TZ"] = timezone_iana  # Cho Date.toString() trong Node VM khớp timezone fingerprint p của Python

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                cwd=str(_PROJECT_ROOT),
                timeout=_RUNNER_TIMEOUT,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"sentinel-runner.js thực thi quá thời gian (>{_RUNNER_TIMEOUT}s），flow={flow}"
            ) from exc
        except FileNotFoundError as exc:
            raise RuntimeError(
                "Không tìm thấy tệp thực thi Node. Hãy xác nhận đã cài Node.js và thêm vào PATH, "
                "hoặc chỉ đường dẫn tuyệt đối qua biến môi trường NODE_EXECUTABLE."
            ) from exc

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            raise RuntimeError(
                f"sentinel-runner.js mã thoát {proc.returncode}\n"
                f"stderr: {stderr}\n"
                f"stdout: {stdout}"
            )

        token_text = (proc.stdout or "").strip()
        if not token_text:
            raise RuntimeError(
                f"sentinel-runner.js đầu ra rỗng, stderr: {(proc.stderr or '').strip()}"
            )

        # Kiểm tra hợp lệ đơn giản: phải là JSON hợp lệ và chứa các trường then chốt
        try:
            parsed = json.loads(token_text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"runner đầu ra không hợp lệ JSON: {token_text[:200]}"
            ) from exc

        for required_key in ("p", "c", "id", "flow"):
            if required_key not in parsed:
                raise RuntimeError(
                    f"runner đầu ra thiếu trường {required_key}: {token_text[:200]}"
                )

        # Chẩn đoán chi tiết: in tất cả tên trường cấp cao nhất của JSON đầu ra + độ dài giá trị
        field_summary = {
            k: (len(v) if isinstance(v, str) else type(v).__name__)
            for k, v in parsed.items()
        }
        logger.info(
            f"[SentinelRunner] token tạo thành công, flow={flow}, "
            f"có turnstile={'t' in parsed and bool(parsed.get('t'))}, "
            f"có so={bool(parsed.get('_so') or parsed.get('so'))}, "
            f"trường: {field_summary}"
        )
        return token_text

    finally:
        # Dọn dẹp tệp tạm
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

# -*- coding: utf-8 -*-
"""
Module tạo Sentinel Token
Đảo ngược từ sdk.js của sentinel.openai.com

Logic cốt lõi:
1. Sinh trường `p` (dữ liệu fingerprint trình duyệt, mảng JSON mã hóa base64)
2. Gửi POST tới sentinel.openai.com/backend-api/sentinel/req
3. Parse token, turnstile, proofofwork trong phản hồi
4. Tính Proof of Work (hash FNV-1a)
5. Ghép giá trị header openai-sentinel-token cuối cùng
"""
import json
import time
import math
import random
import base64
import hashlib
from datetime import datetime, timezone, timedelta

from config import (
    USER_AGENT, SENTINEL_SV, NAVIGATOR_LANGUAGE, NAVIGATOR_LANGUAGES,
    TIMEZONE_OFFSET_MINUTES, TIMEZONE_NAME, SCREEN_WIDTH, SCREEN_HEIGHT,
    HARDWARE_CONCURRENCY, JS_HEAP_SIZE_LIMIT, NAVIGATOR_PROTO_SAMPLES,
    DOCUMENT_KEY_SAMPLES, WINDOW_KEY_SAMPLES, WINDOW_FEATURE_FLAGS,
)


def generate_fingerprint_data(device_id: str, attempt: int = 1, elapsed_ms: float = 0, profile: dict | None = None) -> str:
    """
    Tạo dữ liệu fingerprint trình duyệt (trường p).
    Tương ứng hàm getConfig() + N() trong SDK.

    Cấu trúc mảng getConfig() trả về trong SDK:
    [
        screen.width + screen.height,           # [0] tổng chiều rộng + chiều cao màn hình
        "" + new Date,                           # [1] chuỗi thời gian hiện tại
        performance.memory.jsHeapSizeLimit,      # [2] giới hạn kích thước heap JS
        Math.random() / attempt,                 # [3] số ngẫu nhiên (khi PoW thay bằng số lần thử)
        navigator.userAgent,                     # [4] UA
        src script ngẫu nhiên,                   # [5] src ngẫu nhiên của một thẻ script
        giá trị thuộc tính data-build,           # [6] thuộc tính data-build của document.documentElement
        navigator.language,                      # [7] ngôn ngữ
        navigator.languages.join(","),            # [8] danh sách ngôn ngữ
        Math.random(),                           # [9] số ngẫu nhiên (khi PoW thay bằng thời gian tiêu tốn)
        thuộc tính navigator ngẫu nhiên,         # [10] một phương thức prototype navigator ngẫu nhiên
        key document ngẫu nhiên,                 # [11] một key document ngẫu nhiên
        key window ngẫu nhiên,                   # [12] một key window ngẫu nhiên
        performance.now(),                       # [13] thời gian độ chính xác cao
        sid (UUID),                              # [14] ID phiên
        URL search params,                       # [15] tham số truy vấn URL
        navigator.hardwareConcurrency,           # [16] số lõi CPU
        performance.timeOrigin,                  # [17] gốc thời gian hiệu năng
        Number("ai" in window),                  # [18] window.ai có tồn tại không
        Number("InstallTrigger" in window),      # [19] đặc trưng Firefox → 0
        Number("cache" in window),               # [20] window.cache có tồn tại không
        Number("data" in window),                # [21] window.data có tồn tại không
        Number("solana" in window),              # [22] ví Solana → 0
        Number("dump" in window),                # [23] đặc trưng Firefox → 0
        Number("requestIdleCallback" in window), # [24] có hỗ trợ requestIdleCallback không
    ]

    Args:
        device_id: ID thiết bị
        attempt: số lần thử PoW (dùng để thay [3])
        elapsed_ms: thời gian PoW tính bằng mili giây (dùng để thay [9])
    """
    profile = profile or {}
    screen_width = int(profile.get("screen_width", SCREEN_WIDTH))
    screen_height = int(profile.get("screen_height", SCREEN_HEIGHT))
    js_heap_size_limit = int(profile.get("js_heap_size_limit", JS_HEAP_SIZE_LIMIT))
    hardware_concurrency = int(profile.get("hardware_concurrency", HARDWARE_CONCURRENCY))
    navigator_language = str(profile.get("navigator_language", NAVIGATOR_LANGUAGE))
    navigator_languages = list(profile.get("navigator_languages", NAVIGATOR_LANGUAGES))
    user_agent = str(profile.get("user_agent", USER_AGENT))
    build_id = profile.get("build_id")
    react_listening_key = str(profile.get("react_listening_key") or ("_reactListening" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=11))))
    react_container_key = str(profile.get("react_container_key") or ("__reactContainer$" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=11))))
    react_resources_key = str(profile.get("react_resources_key") or react_container_key.replace("__reactContainer$", "__reactResources$", 1))
    tz_offset = int(profile.get("timezone_offset_minutes", TIMEZONE_OFFSET_MINUTES))
    tz_name = str(profile.get("timezone_name", TIMEZONE_NAME))

    # Mô phỏng môi trường trình duyệt Chrome; Date.toString giữ nhất quán với múi giờ đã cấu hình.
    tz = timezone(timedelta(minutes=tz_offset))
    now = datetime.now(tz)
    sign = "+" if tz_offset >= 0 else "-"
    abs_minutes = abs(tz_offset)
    gmt = f"GMT{sign}{abs_minutes // 60:02d}{abs_minutes % 60:02d}"
    date_str = now.strftime(f"%a %b %d %Y %H:%M:%S {gmt} ({tz_name})")

    # Mô phỏng performance.now() và performance.timeOrigin, giữ
    # timeOrigin + now ≈ Date.now(), tránh mâu thuẫn thời gian trong cùng một mảng p.
    perf_now = random.uniform(1000, 8000)
    time_origin = time.time() * 1000 - perf_now

    # Tạo sid (ID phiên nội bộ SDK)
    sid = str(device_id)

    # Dùng chung cùng một nhóm khóa ứng viên với môi trường JS VM của sentinel-runner.js;
    # SDK mỗi lần sẽ lấy mẫu ngẫu nhiên, giá trị mẫu có thể thay đổi, nhưng tập ứng viên phải thực sự tồn tại.
    navigator_props = list(profile.get("navigator_proto_samples") or NAVIGATOR_PROTO_SAMPLES)
    document_keys = list(profile.get("document_key_samples") or DOCUMENT_KEY_SAMPLES)
    window_keys = list(profile.get("window_key_samples") or WINDOW_KEY_SAMPLES)
    window_flags = dict(WINDOW_FEATURE_FLAGS)
    window_flags.update(profile.get("window_feature_flags") or {})
    script_src_samples = list(profile.get("script_src_samples") or [f"https://sentinel.openai.com/sentinel/{SENTINEL_SV}/sdk.js"])

    config = [
        screen_width + screen_height,       # [0] screen.width + screen.height
        date_str,                        # [1] Chuỗi thời gian
        js_heap_size_limit,              # [2] jsHeapSizeLimit
        attempt,                         # [3] Số lần thử PoW / Math.random()
        user_agent,                      # [4] UA
        random.choice(script_src_samples),  # [5] script src
        build_id,                        # [6] data-build
        navigator_language,              # [7] navigator.language
        ",".join(navigator_languages),   # [8] navigator.languages
        round(elapsed_ms) if elapsed_ms else random.randint(1, 100),  # [9] Thời gian / Math.random()
        random.choice(navigator_props),  # [10] Thuộc tính navigator ngẫu nhiên
        random.choice(document_keys + [react_listening_key, react_container_key, react_resources_key]),  # [11] document key ngẫu nhiên / key inject React
        random.choice(window_keys),       # [12] window key ngẫu nhiên
        round(perf_now, 10),             # [13] performance.now()
        sid,                             # [14] sid
        "",                              # [15] URL search params (trang đăng ký thường trống)
        hardware_concurrency,            # [16] hardwareConcurrency
        round(time_origin, 1),           # [17] performance.timeOrigin
        int(window_flags.get("ai", 0)),                 # [18] Number("ai" in window)
        int(window_flags.get("InstallTrigger", 0)),     # [19] Đặc thù Firefox
        int(window_flags.get("cache", 0)),              # [20] Number("cache" in window)
        int(window_flags.get("data", 0)),               # [21] Number("data" in window)
        int(window_flags.get("solana", 0)),             # [22] Extension ví
        int(window_flags.get("dump", 0)),               # [23] Đặc thù Firefox
        int(window_flags.get("requestIdleCallback", 0)), # [24] Safari mặc định không expose requestIdleCallback
    ]
    return config


def encode_config(config: list) -> str:
    """
    Mã hóa mảng config thành chuỗi base64.
    Tương ứng hàm N() trong SDK:
        JSON.stringify(t) → TextEncoder.encode() → btoa(String.fromCharCode(...))

    Lưu ý: SDK dùng TextEncoder mã hóa chuỗi JSON thành byte UTF-8, rồi btoa từng byte.
    Tương đương Python: json_str.encode('utf-8') → base64 encode
    """
    json_str = json.dumps(config, ensure_ascii=False, separators=(',', ':'))
    # Dùng mã hóa UTF-8 rồi xử lý base64 (giống TextEncoder + btoa của SDK)
    encoded = base64.b64encode(json_str.encode('utf-8')).decode('ascii')
    return encoded


def fnv1a_hash(text: str) -> str:
    """
    Thuật toán băm FNV-1a (32-bit).
    Tương ứng hàm hash trong SDK, dùng để kiểm tra Proof of Work.

    Mã JS gốc：
        let e = 2166136261;
        for (let r = 0; r < t.length; r++)
            e ^= t.charCodeAt(r),
            e = Math.imul(e, 16777619) >>> 0;
        e ^= e >>> 16;
        e = Math.imul(e, 2246822507) >>> 0;
        e ^= e >>> 13;
        e = Math.imul(e, 3266489909) >>> 0;
        e ^= e >>> 16;
        return (e >>> 0).toString(16).padStart(8, "0");
    """
    h = 2166136261
    for ch in text:
        h ^= ord(ch)
        # Mô phỏng Math.imul: nhân số nguyên 32-bit
        h = _imul(h, 16777619) & 0xFFFFFFFF

    h ^= (h >> 16)
    h = _imul(h, 2246822507) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = _imul(h, 3266489909) & 0xFFFFFFFF
    h ^= (h >> 16)
    h = h & 0xFFFFFFFF

    return format(h, '08x')


def _imul(a: int, b: int) -> int:
    """
    Mô phỏng Math.imul của JavaScript (nhân số nguyên 32-bit).
    Số nguyên Python không tràn, cần cắt thủ công về 32-bit.
    """
    # Đảm bảo là số nguyên không dấu 32 bit
    a = a & 0xFFFFFFFF
    b = b & 0xFFFFFFFF
    # Phép nhân số nguyên 32 bit
    result = (a * b) & 0xFFFFFFFF
    return result


def solve_proof_of_work(seed: str, difficulty: str, device_id: str, max_attempts: int = 500000, profile: dict | None = None) -> str:
    """
    Tính Proof of Work.

    Logic _runCheck trong SDK:
    1. Gán config[3] = số lần thử (nonce)
    2. Gán config[9] = Math.round(performance.now() - startTime)
    3. Mã hóa config → chuỗi base64 c
    4. Tính fnv1a(seed + c) → hex 8 ký tự
    5. Nếu hex[:len(difficulty)] <= difficulty thì trả về c + "~S"

    Args:
        seed: seed do server trả về
        difficulty: difficulty do server trả về (tiền tố hex)
        device_id: ID thiết bị
        max_attempts: số lần thử tối đa

    Returns:
        chuỗi đáp án PoW, định dạng base64_encoded_config + "~S"
    """
    start_time = time.time() * 1000  # mili-giây

    # Tạo config ban đầu
    config = generate_fingerprint_data(device_id, attempt=0, elapsed_ms=0, profile=profile)

    diff_len = len(difficulty)

    for i in range(max_attempts):
        # Cập nhật số lần thử và thời gian tiêu tốn
        config[3] = i
        config[9] = round(time.time() * 1000 - start_time)

        # Mã hóa thành base64
        encoded = encode_config(config)

        # Tính hash
        hash_input = seed + encoded
        hash_result = fnv1a_hash(hash_input)

        # Kiểm tra xem có đáp ứng yêu cầu độ khó không
        if hash_result[:diff_len] <= difficulty:
            return encoded + "~S"

    # Nếu đạt số lần thử tối đa vẫn chưa tìm thấy, trả về tiền tố lỗi
    return "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D" + encode_config(["e"])


def generate_requirements_token(device_id: str, profile: dict | None = None) -> str:
    """
    Sinh requirements token (giá trị trường p).
    Tương ứng getRequirementsToken() / _generateRequirementsTokenAnswerBlocking() trong SDK

    Đây là giá trị trường p khi gọi sentinel/req lần đầu.
    Chỉ là mã hóa config đơn giản + hậu tố "~S", không cần PoW.
    """
    config = generate_fingerprint_data(device_id, attempt=1, elapsed_ms=0, profile=profile)
    encoded = encode_config(config)
    return "gAAAAAC" + encoded + "~S"


def build_sentinel_request_body(p: str, device_id: str, flow: str) -> str:
    """
    构建 sentinel/req 的请求体。

    Args:
        p: 指纹数据（requirements token）
        device_id: 设备ID
        flow: 流程类型
            - "username_password_create": 步骤6（注册前）
            - "authorize_continue": 步骤9（验证码验证后）
            - "oauth_create_account": 步骤11（创建账号前）
    """
    body = {
        "p": p,
        "id": device_id,
        "flow": flow,
    }
    return json.dumps(body, separators=(',', ':'))


def build_sentinel_token_header(
    p: str,
    turnstile_token: str,
    sentinel_token: str,
    device_id: str,
    flow: str
) -> str:
    """
    Xây dựng giá trị header openai-sentinel-token.

    Định dạng cuối cùng là chuỗi JSON:
    {"p":"<proof>","t":"<turnstile>","c":"<token>","id":"<device_id>","flow":"<flow>"}
    """
    header_value = {
        "p": p,
        "t": turnstile_token or "",
        "c": sentinel_token,
        "id": device_id,
        "flow": flow,
    }
    return json.dumps(header_value, separators=(',', ':'))


def get_enforcement_token(sentinel_response: dict, seed: str, difficulty: str, device_id: str, profile: dict | None = None) -> str:
    """
    Khi có yêu cầu PoW, tính enforcement token (trường p kèm PoW).
    Tương ứng getEnforcementToken() trong SDK.

    Args:
        sentinel_response: JSON phản hồi của sentinel/req
        seed: proofofwork.seed
        difficulty: proofofwork.difficulty
        device_id: ID thiết bị

    Returns:
        Chuỗi kết quả PoW (base64 + ~S)
    """
    pow_data = sentinel_response.get("proofofwork", {})

    if pow_data.get("required"):
        pow_seed = pow_data.get("seed", "")
        pow_difficulty = pow_data.get("difficulty", "")
        answer = solve_proof_of_work(pow_seed, pow_difficulty, device_id, profile=profile)
        return "gAAAAAB" + answer

    # Khi không cần PoW, trả về fingerprint đơn giản
    return generate_requirements_token(device_id, profile=profile)

# -*- coding: utf-8 -*-
"""
Cấu hình kho proxy

Mỗi lần đăng ký rút ngẫu nhiên một proxy, các sid độc lập, giảm liên kết rủi ro.

Giao thức:
    - http:// / https://   proxy HTTP(S)
    - socks5://            SOCKS5 (DNS phân giải local, có thể lộ)
    - socks5h://           SOCKS5 (DNS phân giải ở proxy, nên dùng, tránh lệch DNS-IP)
"""
import random
from urllib.parse import quote, urlparse

from config.env_loader import apply_env_overrides


# Cổng proxy local; vùng đầu ra thực tế theo rule proxy/chia tuyến.
# Nên dùng socks5h:// (DNS phân giải ở proxy), tránh DNS local lệch vùng với IP đầu ra.
PROXY_POOL = [
    "socks5://127.0.0.1:7897",
]

# Proxy upstream local của kho proxy. Điền thì thành: upstream local -> proxy đích trong kho -> ChatGPT;
# để trống thì dùng thẳng proxy đích trong kho, không bật relay chuỗi.
PROXY_POOL_UPSTREAM_PROXY = ""

# Tra tư cách gói/dùng thử Plus và tạo Codex Agent Token dùng chung nhóm chính sách mạng này,
# tránh request hàng loạt bị proxy local tạm trong kho đăng ký kéo sập, và tránh đi thẳng vô điều kiện làm mất kiểm soát đầu ra.
#   auto   = ưu tiên PLAN_CHECK_PROXY hoặc kho proxy; không có proxy mới chạy direct
#   proxy  = ép PLAN_CHECK_PROXY hoặc kho proxy, thất bại thì báo lỗi
#   direct = luôn đi thẳng
PLAN_CHECK_PROXY_MODE = "auto"

# Proxy riêng tra gói / tạo Codex Agent Token. auto/proxy để trống thì chọn từ PROXY_POOL.
# Proxy có thể chứa tài khoản/mật khẩu, nên WebUI lưu vào .env.
PLAN_CHECK_PROXY = []

# Proxy upstream cho tra gói / tạo Codex Agent Token. Điền thì thành: proxy local -> proxy động -> ChatGPT.
# Ví dụ http://127.0.0.1:7897; để trống thì nối thẳng PLAN_CHECK_PROXY.
PLAN_CHECK_UPSTREAM_PROXY = ""

# Tra gói / tạo Codex Agent Token dùng timeout ngắn và số lần thử giới hạn riêng, tránh tác vụ nền kẹt lâu.
PLAN_CHECK_TIMEOUT = 15.0
PLAN_CHECK_MAX_ATTEMPTS = 3
PLAN_CHECK_RETRY_DELAY = 2.0

# Quyền lợi tài khoản mới đăng ký có thể trễ đồng bộ ngắn. Lần tra đầu thất bại, hoặc trả free và chưa thấy
# tư cách dùng thử Plus, chờ số giây này rồi tra lại; 0 = tắt tra lại.
PLAN_CHECK_REGISTRATION_RECHECK_DELAY = 2.0

# Tra gói tự động, thủ công và hàng loạt dùng chung một hàng đợi nền; Codex Agent Token dùng hàng đợi riêng,
# nhưng tái dùng chế độ mạng, khoảng khởi động request và jitter ở đây, tránh request nền hàng loạt dồn cục.
PLAN_CHECK_WORKERS = 3
PLAN_CHECK_QUEUE_LIMIT = 500
PLAN_CHECK_MIN_INTERVAL = 1.0
PLAN_CHECK_JITTER = 0.8


def _valid_port(value: str) -> bool:
    return value.isdigit() and 1 <= int(value) <= 65535


def normalize_proxy_url(value: str, default_scheme: str = "http") -> str:
    """Normalize common proxy shorthand while preserving explicit URLs."""
    text = str(value or "").strip()
    if not text or "://" in text:
        return text
    parts = text.split(":", 3)
    if len(parts) == 4 and parts[0] and _valid_port(parts[1]) and parts[2] and parts[3]:
        host, port, username, password = parts
        return f"{default_scheme}://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
    if len(parts) == 4 and parts[0] and parts[1] and parts[2] and _valid_port(parts[3]):
        username, password, host, port = parts
        return f"{default_scheme}://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
    parsed = urlparse(f"//{text}")
    try:
        port = parsed.port
    except ValueError:
        port = None
    if parsed.hostname and port:
        return f"{default_scheme}://{text}"
    return text


def normalize_proxy_list(values, default_scheme: str = "http") -> list[str]:
    """Normalize a multiline proxy list and omit empty entries."""
    if values is None:
        return []
    if isinstance(values, str):
        values = values.splitlines()
    return [
        normalized
        for value in values
        if (normalized := normalize_proxy_url(value, default_scheme=default_scheme))
    ]


def pick_proxy() -> str:
    """Rút ngẫu nhiên một URL proxy từ kho; kho trống thì trả chuỗi rỗng (không dùng proxy)."""
    return random.choice(PROXY_POOL) if PROXY_POOL else ""


# Cổng tương thích: mỗi lần tiến trình khởi động rút ngẫu nhiên một proxy, cố định suốt lần đăng ký đó
PROXY = pick_proxy()

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {
    'PROXY_POOL': 'list_str_multiline',
    'PROXY_POOL_UPSTREAM_PROXY': 'str',
    'PLAN_CHECK_PROXY_MODE': 'str',
    'PLAN_CHECK_PROXY': 'list_str_multiline',
    'PLAN_CHECK_UPSTREAM_PROXY': 'str',
    'PLAN_CHECK_TIMEOUT': 'float',
    'PLAN_CHECK_MAX_ATTEMPTS': 'int',
    'PLAN_CHECK_RETRY_DELAY': 'float',
    'PLAN_CHECK_REGISTRATION_RECHECK_DELAY': 'float',
    'PLAN_CHECK_WORKERS': 'int',
    'PLAN_CHECK_QUEUE_LIMIT': 'int',
    'PLAN_CHECK_MIN_INTERVAL': 'float',
    'PLAN_CHECK_JITTER': 'float',
})
PROXY_POOL = normalize_proxy_list(PROXY_POOL)
PLAN_CHECK_PROXY = normalize_proxy_list(PLAN_CHECK_PROXY)
PROXY = pick_proxy()

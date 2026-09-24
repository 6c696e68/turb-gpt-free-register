# -*- coding: utf-8 -*-
"""
Cấu hình nhịp thao tác người.

Request giao thức rất nhanh; thao tác người trên trình duyệt thật thường có dừng tải trang, đọc, gõ,
chuyển email. Tập trung delay ngẫu nhiên nhẹ ở đây, tránh nhịp cố định suốt luồng.
"""
from config.env_loader import apply_env_overrides

# Công tắc chính. Tắt thì delay() trả về ngay.
ENABLE_HUMANIZE_DELAY = True

# Hệ số delay; hàng loạt quá chậm thì hạ xuống 0.5.
HUMANIZE_DELAY_FACTOR = 1.0

# Ngẫu nhiên hoá thao tác tự động Roxy/Cloak. Bật thì click/gõ gần người hơn:
# - Trước click cuộn nhẹ, di chuyển tới vị trí ngẫu nhiên trong phần tử, dừng ngắn rồi click
# - Gõ theo nhịp ngẫu nhiên từng ký tự/đoạn nhỏ, không send_keys cả chuỗi một lần
# - Sau khi mở trang, dừng ngẫu nhiên / di chuột một chút
ENABLE_HUMANIZE_BROWSER_ACTIONS = True

# Khoảng dừng ngẫu nhiên mỗi loại thao tác (giây).
HUMANIZE_DELAYS = {
    # Khoảng API thường: giống JS trang xử lý trạng thái sau một request.
    "api": (0.45, 1.35),
    # Sau chuyển trang / redirect, chờ trang ổn định.
    "navigate": (1.2, 3.2),
    # Liên quan Sentinel / Turnstile / PoW, chừa thời gian SDK chạy và UI chờ.
    "challenge": (0.8, 2.4),
    # Sau khi mã OTP email tới, giả lập người quay lại trang và gõ.
    "otp_input": (2.5, 8.0),
    # Điền form tên, ngày sinh.
    "form": (1.8, 5.0),
    # Sau đăng ký vào app, kéo session.
    "post_auth": (1.5, 4.0),
    # Lệch pha tác vụ đồng thời.
    "job_stagger": (0.4, 1.8),
    # Quan sát / di chuột trước khi click.
    "click": (0.15, 0.85),
    # Khoảng cách gõ một ký tự.
    "keystroke": (0.035, 0.18),
    # Thỉnh thoảng dừng giữa lúc gõ.
    "typing_pause": (0.18, 0.75),
    # Quan sát ngắn sau khi mở trang.
    "page_warmup": (0.7, 2.2),
}

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'ENABLE_HUMANIZE_DELAY': 'bool', 'HUMANIZE_DELAY_FACTOR': 'float', 'ENABLE_HUMANIZE_BROWSER_ACTIONS': 'bool'})

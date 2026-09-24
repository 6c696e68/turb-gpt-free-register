# -*- coding: utf-8 -*-
"""
Cấu hình 2FA (TOTP)

Có tự đặt 2FA sau đăng ký thành công không:
    True:  đăng ký xong → lấy email OTP mới → enroll TOTP → activate → ghi secret vào DB
    False: bỏ cả luồng 2FA, chỉ lưu email + accessToken

Tắt 2FA không ảnh hưởng dùng được tài khoản; chỉ là không có mã động, và ít hơn một email OTP.
"""
from config.env_loader import apply_env_overrides

ENABLE_2FA = False

# Chế độ proxy mạng 2FA:
#   saved = ưu tiên proxy hợp lệ đã lưu của tài khoản (không có thì về kho proxy)
#   pool  = bỏ proxy đã lưu, mỗi tác vụ rút ngẫu nhiên từ PROXY_POOL
TWOFA_PROXY_MODE = "saved"

# Thử lại lỗi mạng tạm khi khởi tạo reauth (CSRF + signin). 403 xoá circuit-breaker
# local của phiên hiện tại rồi thử lại theo backoff mũ; 4xx nghiệp vụ không thử lại.
TWOFA_REAUTH_MAX_ATTEMPTS = 3
TWOFA_REAUTH_RETRY_DELAY = 3.0

# Hàng đợi nền 2FA. workers là số tài khoản chạy đồng thời; đổi xong cần restart để tạo lại pool luồng.
TWOFA_WORKERS = 4
TWOFA_QUEUE_LIMIT = 200

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {
    'ENABLE_2FA': 'bool',
    'TWOFA_PROXY_MODE': 'str',
    'TWOFA_REAUTH_MAX_ATTEMPTS': 'int',
    'TWOFA_REAUTH_RETRY_DELAY': 'float',
    'TWOFA_WORKERS': 'int',
    'TWOFA_QUEUE_LIMIT': 'int',
})

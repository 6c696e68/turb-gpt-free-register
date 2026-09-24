# -*- coding: utf-8 -*-
"""
Thông tin đăng ký cơ bản (mặc định)

CLI qua main.py đọc ở đây trước; console Web đăng ký hàng loạt cũng dùng mặc định này.
Field trống sẽ hỏi tương tác hoặc tự sinh (chỉ khi USE_EMAIL_SERVICE=True email được lấy từ kho Outlook).
"""
from config.env_loader import apply_env_overrides

# Email đăng ký (trống + USE_EMAIL_SERVICE=True thì lấy từ kho Outlook)
REGISTER_EMAIL = ""

# Mật khẩu đăng ký (luồng OTP-only không cần, giữ dự phòng)
REGISTER_PASSWORD = ""

# Tên người dùng (tên hiển thị đặt sau đăng ký; trống thì sinh dạng "Foo Bar")
# Giới hạn OpenAI: name_invalid_chars — chỉ chữ và khoảng trắng
REGISTER_NAME = ""

# Sau khi đăng ký lưu DB có tự tra cứu tư cách gói/Plus không.
# Tắt thì không gọi backend-api/accounts/check ngay sau đăng ký; sau đó tra cứu tay trên danh sách tài khoản.
AUTO_PLAN_CHECK_AFTER_REGISTER = False

# Sau đăng ký và có accessToken, dừng ngẫu nhiên trong trình duyệt rồi mới đóng kết nối.
# Định dạng: giây tối thiểu,giây tối đa. "0,0" = không dừng thêm.
POST_REGISTER_DWELL_SECONDS_RANGE = "5,15"

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {
    'REGISTER_EMAIL': 'str',
    'REGISTER_NAME': 'str',
    'AUTO_PLAN_CHECK_AFTER_REGISTER': 'bool',
    'POST_REGISTER_DWELL_SECONDS_RANGE': 'str',
})

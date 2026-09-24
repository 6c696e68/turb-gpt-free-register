# -*- coding: utf-8 -*-
"""
Cấu hình tự gọi Flow sau khi đăng ký thành công.
ENABLE_FLOW_TRIGGER = False thì bỏ hẳn bước này.
"""
from config.env_loader import apply_env_overrides

# Có tự gọi Flow không (False = bỏ qua, không ảnh hưởng kết quả đăng ký)
ENABLE_FLOW_TRIGGER: bool = False

# Địa chỉ API trigger Flow
FLOW_TRIGGER_URL: str = ""

# Bearer Token (header Authorization)
FLOW_TRIGGER_BEARER: str = ""

# Chuỗi Cookie
FLOW_TRIGGER_COOKIE: str = ""

# JSON payload gửi đi (access_token được inject vào)
FLOW_TRIGGER_PAYLOAD: dict = {}

# Timeout request (giây)
FLOW_TRIGGER_TIMEOUT: int = 15

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'ENABLE_FLOW_TRIGGER': 'bool'})

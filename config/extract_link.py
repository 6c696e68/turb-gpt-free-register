# -*- coding: utf-8 -*-
"""Cấu hình dịch vụ rút link dùng thử Plus."""
from config.env_loader import apply_env_overrides

# Địa chỉ dịch vụ rút link
EXTRACT_LINK_API_BASE: str = ""

# CDK rút link; cần cho cả tạo tác vụ và lắng nghe sự kiện.
EXTRACT_LINK_CDK: str = ""

# Loại rút link: pix / upi / kakao_pay / ideal
EXTRACT_LINK_TYPE: str = "pix"

# Đồng thời và timeout rút link nền
EXTRACT_LINK_WORKERS: int = 3
EXTRACT_LINK_QUEUE_LIMIT: int = 500
EXTRACT_LINK_REQUEST_TIMEOUT: int = 30
EXTRACT_LINK_EVENT_TIMEOUT: int = 180

apply_env_overrides(globals(), {
    'EXTRACT_LINK_API_BASE': 'str',
    'EXTRACT_LINK_CDK': 'str',
    'EXTRACT_LINK_TYPE': 'str',
    'EXTRACT_LINK_WORKERS': 'int',
    'EXTRACT_LINK_QUEUE_LIMIT': 'int',
    'EXTRACT_LINK_REQUEST_TIMEOUT': 'int',
    'EXTRACT_LINK_EVENT_TIMEOUT': 'int',
})

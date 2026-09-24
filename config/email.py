# -*- coding: utf-8 -*-
"""
Cấu hình dịch vụ email.

Hành vi kho mặc định cho email đăng ký Outlook và OTP:
    1. Lần chạy đầu migrate `用于注册的邮箱.txt` cũ sang SQLite
    2. Trong lúc chạy, nhập và quản lý email qua WebUI «Kho email»
    3. Lúc đăng ký lấy thẳng email khả dụng từ kho SQLite
"""
from config.env_loader import env_str, apply_env_overrides


# True: REGISTER_EMAIL trống thì tự lấy email từ kho tài khoản Outlook, OTP tự nhận
# False: nhập email tay và điền OTP tay
USE_EMAIL_SERVICE = False

# Giá trị (có thể nhiều nguồn, phân tách bằng dấu phẩy, fallback theo thứ tự, ví dụ "outlook,generic_api,mailnest,remail"):
#   "outlook"           — kho tài khoản Outlook mua ngoài + lấy thư remote mail.chatai.codes
#   "cloudflare_domain" — email domain Cloudflare (forward sang email QQ), lấy thư qua IMAP
#   "cloudflare" — email tạm Cloudflare Worker (cloudflare_temp_email), API tạo và lấy mã
#   "generic_api"       — kho email lấy mã API chung (email----URL lấy mã)
#   "imap"              — kho IMAP chung (mỗi vật liệu gồm server và thông tin đăng nhập)
#   "gptmail"           — API email tạm GPTMail (lúc chạy sinh email ngẫu nhiên và tự nhận mã)
#   "mailnest"          — API email tạm MailNest (lúc chạy mua email và tự nhận mã)
#   "cloudmail"         — CloudMail/Cloud Mail API (tự lấy domain từ nền tảng và sinh email ngẫu nhiên)
#   "remail"            — Remail Open API (đặt hàng theo dự án và tự nhận mã OTP)
EMAIL_SOURCE = "outlook,generic_api,mailnest"


# ============================================================
# Chế độ Outlook (kho tài khoản mua ngoài + dịch vụ lấy thư)
# ============================================================

OUTLOOK_ACCOUNTS_FILE = "用于注册的邮箱.txt"

# Chế độ lấy thư Outlook:
#   "auto"   = remote mail.chatai.codes trước; remote 402/DEPLOYMENT_DISABLED thì chuyển Microsoft Graph trực tiếp
#   "remote" = chỉ remote mail.chatai.codes
#   "direct" = chỉ Microsoft Graph trực tiếp (clientId + refreshToken đổi access_token)
OUTLOOK_FETCH_MODE = "auto"

# Gốc URL API lấy thư (chế độ remote)
OUTLOOK_API_BASE = "https://mail.chatai.codes"


# ============================================================
# Tham số poll OTP
# ============================================================

OTP_POLL_INTERVAL = 3
OTP_MAX_WAIT = 90

# Lấy thư Outlook hai giao thức: sau khi bắt được một OTP, chờ thêm bao nhiêu giây xem có thư đến muộn hơn.
OTP_SETTLE_SECONDS = 5

# Proxy riêng lấy mã API chung; không đọc kho proxy, cũng không áp chuỗi upstream kho proxy.
# Proxy API local điền thẳng http://127.0.0.1:7897; để trống thì đi thẳng.
GENERIC_API_PROXY: str = "http://127.0.0.1:7897"

# Thư mục hộp thư mặc định IMAP chung; server, cổng và credential đi theo vật liệu email lúc nhập.
IMAP_MAILBOX = "INBOX"


# ============================================================
# Chế độ email domain Cloudflare (forward sang email QQ, lấy thư qua IMAP)
# ============================================================

# Domain Cloudflare của bạn, ví dụ "mydomain.com"
# Lúc đăng ký tự sinh random@mydomain.com làm email đăng ký
EMAIL_DOMAIN = ""

# Địa chỉ server IMAP email QQ (cố định imap.qq.com)
QQ_IMAP_SERVER = "imap.qq.com"

# Cổng IMAP email QQ (SSL)
QQ_IMAP_PORT = 993

# Địa chỉ email QQ (nhận thư Cloudflare forward), ví dụ "123456@qq.com"
QQ_EMAIL = ""

# Mã uỷ quyền IMAP email QQ (tạo ở webmail QQ → Cài đặt → Tài khoản → dịch vụ POP3/IMAP/SMTP)
# Lưu ý: đây là mã uỷ quyền 16 ký tự, không phải mật khẩu QQ
QQ_IMAP_PASSWORD = env_str("QQ_IMAP_PASSWORD", "")


# ============================================================
# API email tạm GPTMail (địa chỉ cố định: https://mail.chatgpt.org.uk)
# ============================================================

# Bắt buộc khi EMAIL_SOURCE="gptmail"; điền ở WebUI «Cấu hình → Email / OTP».
GPTMAIL_API_KEY = env_str("GPTMAIL_API_KEY", "")


# ============================================================
# Email tạm Cloudflare Worker (tương thích cloudflare_temp_email)
# Bật khi EMAIL_SOURCE chứa "cloudflare"; khác cloudflare_domain (QQ IMAP).
# ============================================================

# Gốc API Worker, ví dụ https://mail.example.com
CLOUDFLARE_API_BASE = env_str("CLOUDFLARE_API_BASE", "")

# Chế độ ẩn danh có thể để trống; chế độ admin điền ADMIN_PASSWORD
CLOUDFLARE_API_KEY = env_str("CLOUDFLARE_API_KEY", "")

# none / bearer / x-api-key / x-admin-auth / query-key
CLOUDFLARE_AUTH_MODE = "none"

# Mật khẩu toàn cục Worker (PASSWORDS), inject header x-custom-auth
CLOUDFLARE_CUSTOM_AUTH = env_str("CLOUDFLARE_CUSTOM_AUTH", "")

CLOUDFLARE_PATH_DOMAINS = "/api/domains"
CLOUDFLARE_PATH_ACCOUNTS = "/api/new_address"
CLOUDFLARE_PATH_TOKEN = "/api/token"
CLOUDFLARE_PATH_MESSAGES = "/api/mails"

# Domain nhận thư mặc định, nhiều domain cách nhau bằng xuống dòng hoặc dấu phẩy; để trống thì Worker quyết định
CLOUDFLARE_DEFAULT_DOMAINS = []

CLOUDFLARE_REQUEST_TIMEOUT = 20
CLOUDFLARE_NAME_LENGTH = 10


# ============================================================
# Email tạm Outlook MailNest: https://mailnest.top/
# ============================================================

# Bắt buộc khi EMAIL_SOURCE="mailnest"; điền ở WebUI «Cấu hình → Email / OTP».
MAIL_NEST_API_KEY = env_str("MAIL_NEST_API_KEY", "")

# Mã dự án MailNest; OpenAI/ChatGPT mặc định chatgpt001.
MAIL_NEST_PROJECT_CODE = "chatgpt001"

# ============================================================
# Tài liệu CloudMail API: https://doc.skymail.ink/api/api-doc
# ============================================================

# Địa chỉ Cloud Mail Worker/API, ví dụ: https://mail.example.com
CLOUDMAIL_API_BASE = ""

# Email/mật khẩu admin CloudMail; dùng tạo Token tay, và tự đăng nhập lấy domain khi domain bị ẩn.
CLOUDMAIL_ADMIN_EMAIL = env_str("CLOUDMAIL_ADMIN_EMAIL", "")
CLOUDMAIL_PASSWORD = env_str("CLOUDMAIL_PASSWORD", "")

# Path API tạo Token CloudMail; mặc định theo kiểu public API Cloud Mail.
CLOUDMAIL_TOKEN_PATH = "/api/public/genToken"

# Authorization Token CloudMail/Cloud Mail API; điền tay hoặc tự lấy bằng tài khoản/mật khẩu.
CLOUDMAIL_AUTH_TOKEN = env_str("CLOUDMAIL_AUTH_TOKEN", "")

# Danh sách domain email, mỗi dòng một domain hoặc phân tách bằng dấu phẩy; để trống thì lúc chạy tự lấy từ CloudMail.
CLOUDMAIL_DOMAINS = []

# Sau khi sinh email có gọi /api/public/addUser để tạo user email không.
CLOUDMAIL_AUTO_ADD_USER = True

# Độ dài local-part email ngẫu nhiên.
CLOUDMAIL_RANDOM_LOCAL_LENGTH = 12


# ============================================================
# Remail Open API: https://remail.aishop6.com/docs
# ============================================================

# Gốc API; cũng chấp nhận https://remail.aishop6.com/docs, client tự chuẩn hoá.
REMAIL_API_BASE = "https://remail.aishop6.com"

# API Key đầu rk- tạo ở console Remail.
REMAIL_API_KEY = env_str("REMAIL_API_KEY", "")

# Chọn project ID mã OTP ChatGPT/OpenAI trong danh sách dự án Remail, mặc định dự án 2.
REMAIL_PROJECT_ID = 2

# Hậu tố email khi đặt hàng theo dự án; outlook.com là lựa chọn thường cho hàng email Microsoft.
REMAIL_EMAIL_SUFFIX = "outlook.com"

# code là nhận mã ngắn hạn; purchase là mua dài hạn nhận thư lặp lại, mặc định purchase.
REMAIL_SERVICE_MODE = "purchase"

# private_first ưu tiên tồn kho của mình; public_only chỉ dùng tồn kho công khai, mặc định public_only.
REMAIL_SUPPLY_POLICY = "public_only"

# Khi phản hồi đặt hàng chưa trả service token ngay, số giây tối đa chờ chi tiết đơn bổ sung credential.
REMAIL_ORDER_WAIT_SECONDS = 30

# Timeout request HTTP Remail.
REMAIL_REQUEST_TIMEOUT = 20

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'USE_EMAIL_SERVICE': 'bool', 'OTP_MAX_WAIT': 'int', 'OTP_POLL_INTERVAL': 'int', 'OTP_SETTLE_SECONDS': 'int', 'GENERIC_API_PROXY': 'str', 'EMAIL_SOURCE': 'str', 'IMAP_MAILBOX': 'str', 'EMAIL_DOMAIN': 'str', 'QQ_EMAIL': 'str', 'QQ_IMAP_PASSWORD': 'str', 'GPTMAIL_API_KEY': 'str', 'OUTLOOK_FETCH_MODE': 'str', 'MAIL_NEST_API_KEY': 'str', 'MAIL_NEST_PROJECT_CODE': 'str', 'CLOUDFLARE_API_BASE': 'str', 'CLOUDFLARE_API_KEY': 'str', 'CLOUDFLARE_AUTH_MODE': 'str', 'CLOUDFLARE_CUSTOM_AUTH': 'str', 'CLOUDFLARE_PATH_DOMAINS': 'str', 'CLOUDFLARE_PATH_ACCOUNTS': 'str', 'CLOUDFLARE_PATH_TOKEN': 'str', 'CLOUDFLARE_PATH_MESSAGES': 'str', 'CLOUDFLARE_DEFAULT_DOMAINS': 'list_str_multiline', 'CLOUDFLARE_REQUEST_TIMEOUT': 'int', 'CLOUDFLARE_NAME_LENGTH': 'int', 'CLOUDMAIL_API_BASE': 'str', 'CLOUDMAIL_ADMIN_EMAIL': 'str', 'CLOUDMAIL_PASSWORD': 'str', 'CLOUDMAIL_TOKEN_PATH': 'str', 'CLOUDMAIL_AUTH_TOKEN': 'str', 'CLOUDMAIL_DOMAINS': 'list_str_multiline', 'CLOUDMAIL_AUTO_ADD_USER': 'bool', 'CLOUDMAIL_RANDOM_LOCAL_LENGTH': 'int', 'REMAIL_API_BASE': 'str', 'REMAIL_API_KEY': 'str', 'REMAIL_PROJECT_ID': 'int', 'REMAIL_EMAIL_SUFFIX': 'str', 'REMAIL_SERVICE_MODE': 'str', 'REMAIL_SUPPLY_POLICY': 'str', 'REMAIL_ORDER_WAIT_SECONDS': 'int', 'REMAIL_REQUEST_TIMEOUT': 'int'})

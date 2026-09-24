# -*- coding: utf-8 -*-
"""
Lớp đọc/ghi cấu hình (dùng cho WebUI /api/config).

Nguyên tắc thiết kế:
    1. Whitelist: chỉ expose các công tắc/giá trị số/giá trị mặc định "an toàn runtime"; hằng số cấp giao thức
       (client_id / scope / phiên bản sentinel v.v.) đều không mở, tránh sửa một chút là hỏng tài khoản.
    2. Mọi mục WebUI chỉnh được ghi thống nhất vào `.env` gốc dự án, không còn sửa `config/*.py`.
    3. `config/*.py` chỉ giữ giá trị mặc định; runtime ghi đè bằng `.env` qua config.env_loader.
    4. Khi đọc ưu tiên `.env`, thiếu thì fallback parse giá trị mặc định từ `config/*.py`.
"""
import ast
import os
import re
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CONFIG_DIR = _PROJECT_ROOT / "config"
EXPLICIT_EMPTY_LIST_KEYS = {
    "PROXY_POOL",
}


# ============================================================
# Whitelist: mỗi mục có thể chỉnh sửa khai báo nó ở file nào, tên khóa, kiểu, nhóm, mô tả
# type quyết định control frontend + định dạng literal khi ghi lại:
#   bool   -> True/False
#   int    -> số nguyên
#   str    -> chuỗi có dấu ngoặc kép
#   list_str_multiline -> danh sách chuỗi nhiều dòng (dành riêng cho PROXY_POOL, thay thế cả khối)
# ============================================================

EDITABLE_FIELDS = [
    # ---- Ủy quyền WebUI ----
    {
        "key": "WEBUI_AUTH_CODE", "file": "codex.py", "type": "str", "group": "Uỷ quyền WebUI",
        "label": "Mã uỷ quyền WebUI", "help": "Chỉ lưu trong .env (WEBUI_AUTH_CODE), tránh hiện trên dòng lệnh tiến trình; sau khi lưu, khởi động lại WebUI để có hiệu lực",
        "storage": "env", "secret": True,
    },
    {
        "key": "WEBUI_SESSION_SECRET", "file": "codex.py", "type": "str", "group": "Uỷ quyền WebUI",
        "label": "Khoá ký Session", "help": "Tuỳ chọn, lưu trong .env (WEBUI_SESSION_SECRET); để trống thì suy ra từ mã uỷ quyền cố định, sửa mã uỷ quyền sẽ làm đăng nhập hiện có hết hiệu lực",
        "storage": "env", "secret": True,
    },
    # ---- Công tắc chức năng ----
    {
        "key": "ENABLE_CODEX_AUTO", "file": "codex.py", "type": "bool", "group": "Công tắc tính năng",
        "label": "Bật Codex OAuth", "help": "Sau khi đăng ký thành công tự chạy uỷ quyền Codex (session mới + nhận mã), ghi file codex-email.json",
    },
    {
        "key": "REGISTRATION_DRIVER", "file": "roxybrowser.py", "type": "str", "group": "Cách đăng ký",
        "label": "Driver đăng ký", "help": "Mặc định nên dùng roxy; protocol=thuần giao thức, dễ khoá tài khoản, không khuyến nghị; roxy=RoxyBrowser; cloak=CloakBrowser; browser_use=Browser Use Cloud+Playwright; skyvern=Skyvern Browser Sessions+Playwright",
    },
    {
        "key": "AUTO_PLAN_CHECK_AFTER_REGISTER", "file": "register.py", "type": "bool", "group": "Cách đăng ký",
        "label": "Tự tra cứu gói sau đăng ký", "help": "Sau khi đăng ký thành công, tự xếp hàng tra cứu gói/quyền Plus; tắt thì chỉ lưu tài khoản, không tự tra cứu gói",
    },

    # ---- CloakBrowser ----
    {
        "key": "CLOAK_HEADLESS", "file": "cloakbrowser.py", "type": "bool", "group": "CloakBrowser",
        "label": "Cloak headless", "help": "True=chạy headless; False=hiện cửa sổ trình duyệt",
    },
    {
        "key": "CLOAK_HUMANIZE", "file": "cloakbrowser.py", "type": "bool", "group": "CloakBrowser",
        "label": "Hành vi người Cloak", "help": "Bật hành vi humanize chuột/bàn phím/cuộn của CloakBrowser",
    },
    {
        "key": "CLOAK_GEOIP", "file": "cloakbrowser.py", "type": "bool", "group": "CloakBrowser",
        "label": "Cloak định vị theo IP đầu ra", "help": "Tự khớp múi giờ/ngôn ngữ/WebRTC IP theo IP egress hiện tại; hỗ trợ proxy chỉ định, proxy hệ thống/VPN",
    },
    {
        "key": "CLOAK_LOCALE", "file": "cloakbrowser.py", "type": "str", "group": "CloakBrowser",
        "label": "Ngôn ngữ Cloak", "help": "Để trống thì tự động; Nhật có thể điền ja-JP, Mỹ en-US",
    },
    {
        "key": "CLOAK_TIMEZONE", "file": "cloakbrowser.py", "type": "str", "group": "CloakBrowser",
        "label": "Múi giờ Cloak", "help": "Để trống thì tự động; Nhật có thể điền Asia/Tokyo, Mỹ America/Los_Angeles",
    },
    {
        "key": "CLOAK_USE_PROXY", "file": "cloakbrowser.py", "type": "bool", "group": "CloakBrowser",
        "label": "Cloak dùng proxy", "help": "Truyền proxy do dự án đưa vào hoặc lấy từ kho proxy cho CloakBrowser",
    },
    {
        "key": "CLOAK_LICENSE_KEY", "file": "cloakbrowser.py", "type": "str", "group": "CloakBrowser",
        "label": "Cloak License", "help": "Pro license; để trống thì dùng binary miễn phí",
    },
    {
        "key": "CLOAK_FINGERPRINT_SEED", "file": "cloakbrowser.py", "type": "str", "group": "CloakBrowser",
        "label": "Seed fingerprint Cloak", "help": "Để trống thì mỗi lần ngẫu nhiên; giá trị cố định giữ cùng fingerprint",
    },
    {
        "key": "CLOAK_USER_DATA_DIR", "file": "cloakbrowser.py", "type": "str", "group": "CloakBrowser",
        "label": "Thư mục người dùng Cloak", "help": "Để trống thì dùng ngữ cảnh tạm; điền đường dẫn để lưu cookies/cache",
    },
    {
        "key": "CLOAK_SELENIUM_TIMEOUT", "file": "cloakbrowser.py", "type": "int", "group": "CloakBrowser",
        "label": "Timeout Cloak", "help": "Timeout chờ trang và phần tử, giây",
    },
    {
        "key": "CLOAK_KEEP_BROWSER_OPEN", "file": "cloakbrowser.py", "type": "bool", "group": "CloakBrowser",
        "label": "Giữ trình duyệt Cloak", "help": "Bật khi gỡ lỗi, không tự đóng sau khi tác vụ kết thúc",
    },

    # ---- Browser Use Cloud ----
    {
        "key": "BROWSER_USE_API_KEY", "file": "browser_use.py", "type": "str", "group": "Browser Use",
        "label": "Browser Use API Key", "help": "Lưu trong .env (BROWSER_USE_API_KEY), không ghi lại config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "BROWSER_USE_PROXY_COUNTRY_CODE", "file": "browser_use.py", "type": "str", "group": "Browser Use",
        "label": "Mã quốc gia proxy", "help": "Mã quốc gia hai ký tự, như jp/us/sg; dùng với residential proxy tích hợp của Browser Use",
    },
    {
        "key": "BROWSER_USE_USE_PROXY", "file": "browser_use.py", "type": "bool", "group": "Browser Use",
        "label": "Dùng proxy tích hợp", "help": "True=tham số kết nối kèm proxyCountryCode; False=không bắt buộc gửi tham số proxy quốc gia",
    },
    {
        "key": "BROWSER_USE_PROFILE_ID", "file": "browser_use.py", "type": "str", "group": "Browser Use",
        "label": "Profile ID", "help": "Tuỳ chọn. Nếu điền sẽ dùng lại cookies/localStorage của profile Browser Use; hàng loạt nên để trống",
    },
    {
        "key": "BROWSER_USE_CDP_BASE", "file": "browser_use.py", "type": "str", "group": "Browser Use",
        "label": "Địa chỉ CDP", "help": "Mặc định wss://connect.browser-use.com",
    },
    {
        "key": "BROWSER_USE_TIMEOUT", "file": "browser_use.py", "type": "int", "group": "Browser Use",
        "label": "Timeout thao tác (giây)", "help": "Timeout thao tác mặc định của Playwright",
    },
    {
        "key": "BROWSER_USE_SESSION_TIMEOUT", "file": "browser_use.py", "type": "int", "group": "Browser Use",
        "label": "keepAlive đám mây (phút)", "help": "timeout/keepAlive truyền cho Browser Use connect URL; chương trình tự giới hạn trong 1-240, nên dùng 240",
    },
    {
        "key": "BROWSER_USE_FAST_MODE", "file": "browser_use.py", "type": "bool", "group": "Browser Use",
        "label": "Chế độ nhanh", "help": "Giảm chờ thêm và độ trễ humanize của Browser Use; nên bật, khi gỡ lỗi có thể tắt",
    },
    {
        "key": "BROWSER_USE_LOG_TIMING", "file": "browser_use.py", "type": "bool", "group": "Browser Use",
        "label": "Nhật ký thời gian", "help": "In thời gian từng giai đoạn Browser Use: kết nối, mở trang, email, OTP, điện thoại, callback",
    },
    {
        "key": "BROWSER_USE_KEEP_BROWSER_OPEN", "file": "browser_use.py", "type": "bool", "group": "Browser Use",
        "label": "Giữ phiên từ xa", "help": "Khi gỡ lỗi có thể không chủ động browser.close(); mặc định False",
    },
    {
        "key": "BROWSER_USE_START_URL", "file": "browser_use.py", "type": "str", "group": "Browser Use",
        "label": "URL bắt đầu", "help": "Mặc định https://chatgpt.com/auth/login",
    },

    # ---- Skyvern Cloud Browser ----
    {
        "key": "SKYVERN_API_KEY", "file": "skyvern.py", "type": "str", "group": "Skyvern",
        "label": "Skyvern API Key", "help": "Lưu trong .env (SKYVERN_API_KEY), dùng để tạo Skyvern Browser Session",
        "storage": "env", "secret": True,
    },
    {
        "key": "SKYVERN_API_BASE", "file": "skyvern.py", "type": "str", "group": "Skyvern",
        "label": "Địa chỉ API", "help": "Mặc định https://api.skyvern.com",
    },
    {
        "key": "SKYVERN_BROWSER_SESSION_TIMEOUT", "file": "skyvern.py", "type": "int", "group": "Skyvern",
        "label": "Timeout session (phút)", "help": "timeout truyền vào khi tạo Skyvern Browser Session",
    },
    {
        "key": "SKYVERN_BROWSER_PROFILE_ID", "file": "skyvern.py", "type": "str", "group": "Skyvern",
        "label": "Browser Profile ID", "help": "Tuỳ chọn, dùng lại Skyvern browser profile",
    },
    {
        "key": "SKYVERN_PROXY_LOCATION", "file": "skyvern.py", "type": "str", "group": "Skyvern",
        "label": "Vùng proxy", "help": "Có thể điền jp/us/gb và các viết tắt khác; sẽ tự chuyển thành enum Skyvern, ví dụ jp→RESIDENTIAL_JP; để trống thì không truyền",
    },
    {
        "key": "SKYVERN_BROWSER_TYPE", "file": "skyvern.py", "type": "str", "group": "Skyvern",
        "label": "Loại trình duyệt", "help": "Skyvern hỗ trợ msedge / chrome / stealth-chromium；giá trị cũ chromium-headful sẽ tự chuyển thành stealth-chromium",
    },
    {
        "key": "SKYVERN_AD_BLOCKER", "file": "skyvern.py", "type": "bool", "group": "Skyvern",
        "label": "Chặn quảng cáo", "help": "Bật ad_blocker khi tạo Skyvern Browser Session",
    },
    {
        "key": "SKYVERN_GENERATE_BROWSER_PROFILE", "file": "skyvern.py", "type": "bool", "group": "Skyvern",
        "label": "Lưu Profile trình duyệt", "help": "Khi Session kết thúc có cho Skyvern tạo/lưu browser profile hay không",
    },
    {
        "key": "SKYVERN_KEEP_BROWSER_OPEN", "file": "skyvern.py", "type": "bool", "group": "Skyvern",
        "label": "Giữ trình duyệt", "help": "Khi gỡ lỗi có thể bật, không chủ động đóng Skyvern Browser Session sau khi tác vụ kết thúc",
    },
    {
        "key": "SKYVERN_START_URL", "file": "skyvern.py", "type": "str", "group": "Skyvern",
        "label": "URL bắt đầu", "help": "Mặc định https://chatgpt.com/auth/login",
    },
    {
        "key": "ROXY_API_BASE", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Địa chỉ Roxy API", "help": "Mặc định http://127.0.0.1:50000; cần bật trong cấu hình API của ứng dụng Roxy",
    },
    {
        "key": "ROXY_API_TOKEN", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Roxy API Key", "help": "Lưu trong .env (ROXY_API_TOKEN), không ghi lại config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "ROXY_PROFILE_ID", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "ID môi trường Roxy", "help": "Chỉ định Profile ID / môi trường Roxy cần mở; để trống thì thử tạo môi trường tạm",
    },
    {
        "key": "ROXY_WORKSPACE_ID", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "ID workspace Roxy", "help": "Bắt buộc khi tạo một tài khoản một môi trường, sẽ gửi làm workspaceId cho API tạo Profile của Roxy",
    },
    {
        "key": "ROXY_PROJECT_ID", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "ID dự án Roxy", "help": "Lấy từ project_details.projectId của /browser/workspace；khi tạo Profile sẽ gửi làm projectId",
    },
    {
        "key": "ROXY_WORKSPACE_LIST_PATH", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "API lấy team", "help": "Mặc định /browser/workspace; khi bấm lấy team/dự án sẽ thử đường dẫn này trước, rồi tự thử các đường dẫn tương thích thường gặp",
    },
    {
        "key": "ROXY_OPEN_PATH", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Đường dẫn API mở", "help": "Mặc định /browser/open; chỉnh nếu bản Roxy khác",
    },
    {
        "key": "ROXY_CREATE_INTERVAL", "file": "roxybrowser.py", "type": "float", "group": "RoxyBrowser",
        "label": "Khoảng cách tạo môi trường", "help": "Khoảng cách tối thiểu giữa các request /browser/create liền kề khi đa luồng, mặc định 1.5 giây; đặt 0 để tắt",
    },
    {
        "key": "ROXY_OPEN_HEADLESS", "file": "roxybrowser.py", "type": "bool", "group": "RoxyBrowser",
        "label": "Mở cửa sổ headless", "help": "Khi mở môi trường Roxy, truyền headless tới /browser/open; False=hiện cửa sổ, True=khởi chạy headless",
    },
    {
        "key": "ROXY_CLOSE_PATH", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Đường dẫn API đóng", "help": "Mặc định /browser/close",
    },
    {
        "key": "ROXY_KEEP_BROWSER_OPEN", "file": "roxybrowser.py", "type": "bool", "group": "RoxyBrowser",
        "label": "Giữ trình duyệt", "help": "Khi gỡ lỗi có thể bật, không tự đóng môi trường Roxy sau khi tác vụ kết thúc",
    },
    {
        "key": "ROXY_ONE_PROFILE_PER_ACCOUNT", "file": "roxybrowser.py", "type": "bool", "group": "RoxyBrowser",
        "label": "Một tài khoản một môi trường", "help": "Mỗi tài khoản bắt buộc tạo Roxy Profile mới, dùng xong thì đóng và xoá, cấm dùng lại môi trường cố định",
    },
    {
        "key": "ROXY_DELETE_PROFILE_AFTER_RUN", "file": "roxybrowser.py", "type": "bool", "group": "RoxyBrowser",
        "label": "Xoá môi trường khi kết thúc", "help": "Ở chế độ một tài khoản một môi trường, xoá Roxy Profile đã tạo trong lượt này sau khi tác vụ kết thúc",
    },
    {
        "key": "ROXY_RANDOM_OS_ON_CREATE", "file": "roxybrowser.py", "type": "bool", "group": "RoxyBrowser",
        "label": "OS ngẫu nhiên khi tạo môi trường", "help": "Khi tạo môi trường Roxy, mỗi lần random Windows / macOS, không cố định macOS",
    },
    {
        "key": "ROXY_RANDOM_OS_CHOICES", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Phạm vi OS ngẫu nhiên", "help": "Phân tách bằng dấu phẩy, mặc định Windows,macOS; Roxy hỗ trợ Windows / macOS / Linux / IOS / Android",
    },
    {
        "key": "ROXY_RANDOM_PROFILE_NAME_ON_CREATE", "file": "roxybrowser.py", "type": "bool", "group": "RoxyBrowser",
        "label": "Tên ngẫu nhiên khi tạo môi trường", "help": "Khi tạo môi trường Roxy, tự sinh tên khác nhau, tránh cố định gpt-free-register",
    },
    {
        "key": "ROXY_PROFILE_NAME_PREFIX", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Tiền tố tên ngẫu nhiên", "help": "Mặc định rb; tên thực tế dạng rb-timestamp-mã ngẫu nhiên",
    },
    {
        "key": "ROXY_CREATE_USE_PROXY_POOL", "file": "roxybrowser.py", "type": "bool", "group": "RoxyBrowser",
        "label": "Tạo môi trường dùng kho proxy", "help": "Khi tạo môi trường Roxy, lấy ngẫu nhiên một proxy từ「Kho proxy」trên trang cấu hình, ghi vào Roxy proxyInfo",
    },
    {
        "key": "ROXY_PROXY_CHECK_CHANNEL", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Kênh kiểm tra proxy", "help": "Ghi Roxy proxyInfo.checkChannel; để trống thì không gửi, mặc định IPRust.io",
    },
    {
        "key": "ROXY_DELETE_PATH", "file": "roxybrowser.py", "type": "str", "group": "RoxyBrowser",
        "label": "Đường dẫn API xoá", "help": "Mặc định /browser/delete; chỉnh nếu bản Roxy khác",
    },
    {
        "key": "CODEX_OAUTH_DRIVER", "file": "codex.py", "type": "str", "group": "Codex",
        "label": "Driver uỷ quyền Codex", "help": "Mặc định nên dùng roxy; protocol=uỷ quyền giao thức gốc; roxy=dùng RoxyBrowser; cloak=dùng CloakBrowser; browser_use=dùng Browser Use Cloud; skyvern=dùng Skyvern; same_as_registration=theo driver đăng ký",
    },
    {
        "key": "ROXY_CODEX_CALLBACK_TIMEOUT", "file": "roxybrowser.py", "type": "int", "group": "RoxyBrowser",
        "label": "Timeout callback Codex", "help": "Số giây tối đa Roxy Codex OAuth chờ callback localhost:1455",
    },
    {
        "key": "ENABLE_2FA", "file": "twofa.py", "type": "bool", "group": "Công tắc tính năng",
        "label": "Bật 2FA (TOTP)", "help": "Sau khi đăng ký xong, tự đặt mật khẩu động (sẽ nhận thêm một email OTP)",
    },
    {
        "key": "TWOFA_PROXY_MODE", "file": "twofa.py", "type": "str", "group": "Công tắc tính năng",
        "label": "Chế độ proxy 2FA", "help": "saved=ưu tiên dùng proxy đã lưu của tài khoản; pool=bỏ qua proxy đã lưu, mỗi lần lấy ngẫu nhiên một proxy từ kho proxy; sau khi sửa cần khởi động lại dịch vụ",
        "choices": [
            {"value": "saved", "label": "Dùng proxy đã lưu của tài khoản"},
            {"value": "pool", "label": "Mỗi lần lấy ngẫu nhiên từ kho proxy"},
        ],
    },
    {
        "key": "TWOFA_WORKERS", "file": "twofa.py", "type": "int", "group": "Công tắc tính năng",
        "label": "Số luồng 2FA", "help": "Số tác vụ bật 2FA chạy cùng lúc, mặc định 4, khoảng 1-16; sửa xong cần khởi động lại dịch vụ",
    },
    {
        "key": "TWOFA_QUEUE_LIMIT", "file": "twofa.py", "type": "int", "group": "Công tắc tính năng",
        "label": "Sức chứa hàng đợi 2FA", "help": "Tổng số tác vụ 2FA được phép chờ hàng, mặc định 200",
    },
    {
        "key": "ENABLE_FLOW_TRIGGER", "file": "flow_trigger.py", "type": "bool", "group": "Công tắc tính năng",
        "label": "Bật kích hoạt Flow", "help": "Sau khi đăng ký thành công, tự gọi API Flow nội bộ (không ảnh hưởng kết quả đăng ký)",
    },
    {
        "key": "ENABLE_HUMANIZE_DELAY", "file": "humanize.py", "type": "bool", "group": "Nhịp thao tác",
        "label": "Bật dừng ngẫu nhiên", "help": "Thêm chờ ngẫu nhiên giữa các bước đăng ký, OTP, uỷ quyền, gần nhịp thao tác người hơn",
    },
    {
        "key": "HUMANIZE_DELAY_FACTOR", "file": "humanize.py", "type": "float", "group": "Nhịp thao tác",
        "label": "Hệ số dừng", "help": "Hệ số chờ ngẫu nhiên; 1.0=mặc định, 0.5=một nửa, 2.0=gấp đôi",
    },
    {
        "key": "ENABLE_HUMANIZE_BROWSER_ACTIONS", "file": "humanize.py", "type": "bool", "group": "Nhịp thao tác",
        "label": "Ngẫu nhiên hoá thao tác trình duyệt", "help": "Roxy/Cloak click, nhập, quan sát trang dùng điểm chuột ngẫu nhiên và nhập từng ký tự, giảm dấu vết thao tác máy",
    },
    # ---- Email / OTP ----
    {
        "key": "USE_EMAIL_SERVICE", "file": "email.py", "type": "bool", "group": "Email / OTP",
        "label": "Tự lấy email và nhận mã", "help": "True=tự lấy email từ kho email và tự nhận OTP; False=chế độ thủ công: dùng REGISTER_EMAIL, OTP điền tay ở trang tác vụ",
    },
    {
        "key": "REGISTER_EMAIL", "file": "register.py", "type": "str", "group": "Email / OTP",
        "label": "Email đăng ký thủ công", "help": "Bắt buộc khi USE_EMAIL_SERVICE=False. Ví dụ địa chỉ outlook.com của bạn; OTP xem ở email web, rồi quay lại trang tác vụ để gửi",
    },
    {
        "key": "REGISTER_NAME", "file": "register.py", "type": "str", "group": "Email / OTP",
        "label": "Tên hiển thị", "help": "Để trống thì tự tạo tên tiếng Anh",
    },
    {
        "key": "OTP_MAX_WAIT", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Chờ OTP tối đa (giây)", "help": "Số giây tối đa chờ email OTP, hết giờ thì thất bại",
    },
    {
        "key": "OTP_POLL_INTERVAL", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Chu kỳ hỏi OTP (giây)", "help": "Bao nhiêu giây thì kiểm tra thư mới một lần",
    },
    {
        "key": "GENERIC_API_PROXY", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Proxy lấy mã API chung", "help": "Chỉ dùng lấy mã qua API generic_api；mặc định đi thẳng proxy HTTP local http://127.0.0.1:7897, không đọc kho proxy, cũng không áp chuỗi upstream kho proxy；để trống thì kết nối trực tiếp",
        "storage": "env",
    },
    {
        "key": "EMAIL_SOURCE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Nguồn email", "help": "Có thể điền một hoặc nhiều, cách nhau bằng dấu phẩy và fallback theo thứ tự：outlook,generic_api,imap,cloudflare_domain,cloudflare,gptmail,mailnest,cloudmail,remail",
    },
    {
        "key": "IMAP_MAILBOX", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Hộp thư IMAP chung", "help": "Thư mục mặc định email IMAP chung, thường là INBOX; server, port, username và mật khẩu khi nhập kho email",
    },
    {
        "key": "GPTMAIL_API_KEY", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "GPTMail API Key", "help": "Bắt buộc khi chọn nguồn email gptmail; lưu trong .env, không ghi vào mã nguồn config",
        "storage": "env", "secret": True,
    },
    {
        "key": "CLOUDFLARE_API_BASE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Địa chỉ Cloudflare API", "help": "Địa chỉ gốc API email tạm của Worker, ví dụ https://mail.example.com; bắt buộc khi chọn cloudflare",
        "storage": "env",
    },
    {
        "key": "CLOUDFLARE_API_KEY", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Cloudflare API Key", "help": "Ẩn danh có thể để trống; chế độ admin điền ADMIN_PASSWORD; lưu trong .env",
        "storage": "env", "secret": True,
    },
    {
        "key": "CLOUDFLARE_AUTH_MODE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Chế độ xác thực Cloudflare", "help": "none / bearer / x-api-key / x-admin-auth / query-key",
    },
    {
        "key": "CLOUDFLARE_CUSTOM_AUTH", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Mật khẩu toàn cục Cloudflare", "help": "Worker PASSWORDS, gắn vào x-custom-auth; lưu trong .env",
        "storage": "env", "secret": True,
    },
    {
        "key": "CLOUDFLARE_PATH_ACCOUNTS", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Đường dẫn tạo Cloudflare", "help": "Mặc định /api/new_address; admin thường dùng /admin/new_address",
    },
    {
        "key": "CLOUDFLARE_PATH_MESSAGES", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Đường dẫn thư Cloudflare", "help": "Mặc định /api/mails",
    },
    {
        "key": "CLOUDFLARE_PATH_DOMAINS", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Đường dẫn tên miền Cloudflare", "help": "Mặc định /api/domains (dự phòng)",
    },
    {
        "key": "CLOUDFLARE_PATH_TOKEN", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Đường dẫn Cloudflare Token", "help": "Mặc định /api/token (dự phòng fallback)",
    },
    {
        "key": "CLOUDFLARE_DEFAULT_DOMAINS", "file": "email.py", "type": "list_str_multiline", "group": "Email / OTP",
        "label": "Tên miền mặc định Cloudflare", "help": "Tên miền nhận thư, mỗi dòng một hoặc cách nhau bằng dấu phẩy; xoay vòng khi tạo, có thể để trống",
    },
    {
        "key": "CLOUDFLARE_REQUEST_TIMEOUT", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Timeout request Cloudflare (giây)", "help": "Timeout request HTTP, mặc định 20",
    },
    {
        "key": "CLOUDFLARE_NAME_LENGTH", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Độ dài tiền tố tên ngẫu nhiên Cloudflare", "help": "Độ dài local-part khi admin tạo, mặc định 10",
    },
    {
        "key": "OUTLOOK_FETCH_MODE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Chế độ lấy thư Outlook", "help": "auto=ưu tiên remote, remote 402/DEPLOYMENT_DISABLED tự chuyển Graph trực tiếp；direct=chỉ Microsoft Graph trực tiếp；remote=chỉ dịch vụ remote",
    },
    {
        "key": "EMAIL_DOMAIN", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Tên miền chuyển tiếp (cloudflare_domain)", "help": "Chỉ dùng cho cloudflare_domain：domain Email Routing, ví dụ mydomain.com；không liên quan EMAIL_SOURCE=cloudflare",
    },
    {
        "key": "QQ_EMAIL", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Địa chỉ email QQ", "help": "Chỉ cloudflare_domain: email QQ nhận chuyển tiếp Email Routing, ví dụ 123456@qq.com",
    },
    {
        "key": "QQ_IMAP_PASSWORD", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Mã uỷ quyền IMAP email QQ", "help": "Chỉ cloudflare_domain: mã uỷ quyền QQ IMAP, lưu trong .env, không ghi ngược vào config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "MAIL_NEST_API_KEY", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "MailNest API Key", "help": "Bắt buộc khi chọn nguồn email mailnest; lưu trong .env, không ghi vào mã nguồn config",
        "storage": "env", "secret": True,
    },
    {
        "key": "MAIL_NEST_PROJECT_CODE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Mã dự án MailNest", "help": "Mã dự án mặc định chatgpt001 trang lấy mailnest.top/buy-email",
    },
    {
        "key": "CLOUDMAIL_API_BASE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Địa chỉ CloudMail API", "help": "Địa chỉ Cloud Mail Worker/API, ví dụ https://mail.example.com",
    },
    {
        "key": "CLOUDMAIL_ADMIN_EMAIL", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Email quản trị CloudMail", "help": "Dùng để tạo Token; khi nền tảng ẩn tên miền cũng dùng nó để đăng nhập và đọc tên miền",
        "storage": "env",
    },
    {
        "key": "CLOUDMAIL_PASSWORD", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Mật khẩu CloudMail", "help": "Dùng để tự lấy Token; lưu trong .env",
        "storage": "env", "secret": True,
    },
    {
        "key": "CLOUDMAIL_TOKEN_PATH", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Đường dẫn CloudMail Token", "help": "Cố định dùng /api/public/genToken; sửa nếu bản triển khai khác",
    },
    {
        "key": "CLOUDMAIL_AUTH_TOKEN", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "CloudMail Token", "help": "CloudMail/Cloud Mail API Authorization Token; lưu trong .env",
        "storage": "env", "secret": True,
    },
    {
        "key": "CLOUDMAIL_DOMAINS", "file": "email.py", "type": "list_str_multiline", "group": "Email / OTP",
        "label": "Danh sách tên miền CloudMail", "help": "Có thể để trống; lúc chạy sẽ tự lấy từ nền tảng. Cũng có thể bấm “Lấy tên miền CloudMail” để lưu cache tại đây",
    },
    {
        "key": "CLOUDMAIL_AUTO_ADD_USER", "file": "email.py", "type": "bool", "group": "Email / OTP",
        "label": "CloudMail tự tạo người dùng", "help": "Sau khi tạo email ngẫu nhiên, gọi /api/public/addUser để tạo người dùng",
    },
    {
        "key": "CLOUDMAIL_RANDOM_LOCAL_LENGTH", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Độ dài tiền tố tên ngẫu nhiên CloudMail", "help": "Độ dài local-part của email, nên 10-16",
    },
    {
        "key": "REMAIL_API_BASE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Địa chỉ Remail API", "help": "Mặc định https://remail.aishop6.com; cũng có thể điền địa chỉ tài liệu https://remail.aishop6.com/docs",
        "external_url": "https://remail.aishop6.com/register?aff=AFFLGYQMTYIXH",
        "external_label": "Mở trang Remail",
    },
    {
        "key": "REMAIL_API_KEY", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Remail API Key", "help": "API Key bắt đầu bằng rk- do bảng điều khiển Remail tạo; bắt buộc khi chọn nguồn remail, lưu trong .env",
        "storage": "env", "secret": True,
    },
    {
        "key": "REMAIL_PROJECT_ID", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "ID dự án Remail", "help": "projectId trong danh sách dự án Remail API, dùng để khớp dự án mã OTP ChatGPT/OpenAI",
    },
    {
        "key": "REMAIL_EMAIL_SUFFIX", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Hậu tố email Remail", "help": "Hậu tố email khi đặt hàng, mặc định outlook.com; đừng điền email đầy đủ",
    },
    {
        "key": "REMAIL_SERVICE_MODE", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Chế độ dịch vụ Remail", "help": "code=nhận mã ngắn hạn; purchase=mua dài hạn (nhận thư lặp lại, mặc định)",
    },
    {
        "key": "REMAIL_SUPPLY_POLICY", "file": "email.py", "type": "str", "group": "Email / OTP",
        "label": "Chiến lược kho Remail", "help": "private_first ưu tiên kho riêng; public_only chỉ dùng kho công khai (mặc định)",
    },
    {
        "key": "REMAIL_ORDER_WAIT_SECONDS", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Chờ đơn Remail (giây)", "help": "Nếu sau khi đặt hàng chưa trả service token ngay, chờ đơn bổ sung thông tin xác thực, mặc định 30 giây",
    },
    {
        "key": "REMAIL_REQUEST_TIMEOUT", "file": "email.py", "type": "int", "group": "Email / OTP",
        "label": "Timeout request Remail (giây)", "help": "Timeout mỗi request HTTP Remail API, mặc định 20 giây",
    },
    # ---- Hồ sơ khu vực trình duyệt ----
    {
        "key": "BROWSER_LOCALE_PROFILE", "file": "browser.py", "type": "str", "group": "Hồ sơ trình duyệt",
        "label": "Hồ sơ vùng", "help": "Nên khớp khu vực egress của proxy; tuỳ chọn jp/cn/us/sg. Proxy local hiện đo được là Tokyo, Nhật Bản, khuyến nghị jp",
    },

    {
        "key": "AUTO_BROWSER_LOCALE_FROM_IP", "file": "browser.py", "type": "bool", "group": "Hồ sơ trình duyệt",
        "label": "Tự dựng hồ sơ theo IP đầu ra", "help": "Sau khi bật, mỗi BrowserSession dùng IP cổng ra proxy hiện tại để tự chọn ngôn ngữ/múi giờ; khi thất bại sẽ fallback về hồ sơ khu vực",
    },
    {
        "key": "IP_GEO_TIMEOUT", "file": "browser.py", "type": "float", "group": "Hồ sơ trình duyệt",
        "label": "Timeout định vị IP (giây)", "help": "Timeout mỗi request API vị trí IP đầu ra; lỗi API thì tự lùi, không ảnh hưởng đăng ký",
    },
    {
        "key": "BROWSER_DATA_SAVER_MODE", "file": "browser.py", "type": "bool", "group": "Hồ sơ trình duyệt",
        "label": "Chế độ tiết kiệm data trình duyệt local", "help": "Chỉ trình duyệt cục bộ Roxy/Cloak chặn tài nguyên tuỳ chọn như ảnh và media; trình duyệt đám mây Browser Use/Skyvern không bật; mặc định tắt",
    },
    {
        "key": "BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES", "file": "browser.py", "type": "list_str_multiline", "group": "Hồ sơ trình duyệt",
        "label": "Loại tài nguyên chặn để tiết kiệm data trình duyệt local", "help": "Chỉ có hiệu lực với Roxy/Cloak；mỗi dòng một loại, mặc định image、media；tuỳ chọn stylesheet、font、manifest、texttrack. Không điền script/xhr/fetch/document/websocket",
    },
    {
        "key": "BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS", "file": "browser.py", "type": "list_str_multiline", "group": "Hồ sơ trình duyệt",
        "label": "Quy tắc chặn URL tiết kiệm data trình duyệt local", "help": "Chỉ có hiệu lực với Roxy/Cloak；mỗi dòng một URL glob；mặc định chặn RUM/thống kê quảng cáo và Google GSI（khi không dùng đăng nhập Google）. Không chặn API/sentinel cốt lõi；điền [] để tắt quy tắc mặc định",
    },
    {
        "key": "BROWSER_TRAFFIC_DETAIL_LOG", "file": "browser.py", "type": "bool", "group": "Hồ sơ trình duyệt",
        "label": "Nhật ký chi tiết traffic trình duyệt local", "help": "Chỉ có hiệu lực với Roxy/Cloak; khi đăng ký kết thúc, xuất URL, loại, phương thức, mã trạng thái và kích thước tải lên/tải xuống của từng tài nguyên; giá trị query URL sẽ được che, mặc định tắt",
    },
    {
        "key": "BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES", "file": "browser.py", "type": "int", "group": "Hồ sơ trình duyệt",
        "label": "Số dòng chi tiết traffic tối đa", "help": "Xuất theo tổng byte mỗi request giảm dần, mặc định 2000, tối đa 10000; dùng để phân tích tài nguyên có thể chặn",
    },
    {
        "key": "BROWSER_JS_COVERAGE_LOG", "file": "browser.py", "type": "bool", "group": "Hồ sơ trình duyệt",
        "label": "Ghi coverage JS trình duyệt local", "help": "Chỉ có hiệu lực với Roxy/Cloak；ghi JS function và offset thực thi của lần đăng ký này qua Chrome CDP；Browser Use/Skyvern không bật；mặc định tắt",
    },
    {
        "key": "BROWSER_JS_COVERAGE_MAX_ENTRIES", "file": "browser.py", "type": "int", "group": "Hồ sơ trình duyệt",
        "label": "Số mục tối đa coverage JS trình duyệt local", "help": "Chỉ có hiệu lực với Roxy/Cloak; số hàm đã chạy tối đa mà nhật ký xuất ra, đồng thời giới hạn số bản tóm tắt script được lưu, mặc định 1000, tối đa 10000",
    },

    # ---- Pool proxy ----
    {
        "key": "PROXY_POOL", "file": "proxy.py", "type": "list_str_multiline", "group": "Kho proxy",
        "label": "Kho proxy (mỗi dòng một)", "help": "Mỗi dòng một URL proxy, dòng trống bị bỏ; để trống thì không dùng proxy",
        "recommended_links": [
            {
                "label": "IP nhà IPWO",
                "url": "https://www.ipwo.net/?code=XEP358YGZ",
                "description": "IPWO proxy dân cư cung cấp tài nguyên IP dân cư phủ 195+ quốc gia và vùng lãnh thổ, hỗ trợ cấu hình môi trường mạng đa khu vực, phù hợp ứng dụng AI, tự động hoá trình duyệt, truy cập dịch vụ nước ngoài và thu thập dữ liệu. Quan trọng! 2GB lưu lượng dân cư động cấp không điều kiện,",
                "description_link_label": "Cổng nhận",
                "description_link_url": "https://www.ipwo.net/?code=XEP358YGZ",
                "description_after_link": ", vào nhóm để nhận ưu đãi IP không định kỳ.",
            },
            {
                "label": "IP nhà IPRocket",
                "url": "https://iprocket.io?viteCode=1PVNyLuJ",
                "description": "IP nhà giá tốt, liên hệ tác giả qua TG để mua traffic",
            },
            {
                "label": "IP nhà Rola-IP",
                "url": "https://rola-ip.co/?code=0326C5HA",
                "description": "IP nhà chất lượng cao của đối tác Roxy, đăng ký được giảm 15%",
            },
        ],
    },
    {
        "key": "PROXY_POOL_UPSTREAM_PROXY", "file": "proxy.py", "type": "str", "group": "Kho proxy",
        "label": "Proxy upstream kho proxy", "help": "Tuỳ chọn; mỗi proxy đích trong kho proxy kết nối qua upstream local này. Để trống thì không chain. Địa chỉ hiển thị plaintext, chỉ lưu vào .env",
        "storage": "env",
    },
    {
        "key": "PLAN_CHECK_PROXY_MODE", "file": "proxy.py", "type": "str", "group": "Kho proxy",
        "label": "Chế độ mạng gói/Agent", "help": "Dùng để tra gói và tạo Agent Token; auto=proxy cục bộ khả dụng thì đi proxy, chưa lắng nghe thì kết nối trực tiếp; proxy=bắt buộc proxy; direct=bắt buộc kết nối trực tiếp",
    },
    {
        "key": "PLAN_CHECK_PROXY", "file": "proxy.py", "type": "list_str_multiline", "group": "Kho proxy",
        "label": "Proxy riêng gói/Agent (mỗi dòng một)", "help": "Dùng để tra gói, kiểm tra sống và tạo Agent Token; hỗ trợ URL proxy động, mỗi dòng một cái. Chỉ lưu vào .env",
        "storage": "env", "secret": True,
    },
    {
        "key": "PLAN_CHECK_UPSTREAM_PROXY", "file": "proxy.py", "type": "str", "group": "Kho proxy",
        "label": "Proxy upstream local gói/Agent", "help": "Tuỳ chọn; chỉ dùng cho proxy chuyên dụng của gói/Agent, tạo chuỗi proxy \"proxy cục bộ -> proxy động -> ChatGPT\". Để trống thì không nối chuỗi. Địa chỉ hiển thị nguyên văn. Chỉ lưu vào .env",
        "storage": "env",
    },
    {
        "key": "PLAN_CHECK_TIMEOUT", "file": "proxy.py", "type": "float", "group": "Kho proxy",
        "label": "Timeout gói/Agent (giây)", "help": "Timeout mỗi request tra gói và tạo Agent Token, nên 10-20 giây; độc lập với timeout request đăng ký",
    },
    {
        "key": "PLAN_CHECK_MAX_ATTEMPTS", "file": "proxy.py", "type": "int", "group": "Kho proxy",
        "label": "Số lần thử tối đa gói/Agent", "help": "Số lần thử lại khi tra cứu gói và tạo Agent Token gặp 403, 429, 5xx hoặc lỗi mạng, nên 3 lần",
    },
    {
        "key": "PLAN_CHECK_RETRY_DELAY", "file": "proxy.py", "type": "float", "group": "Kho proxy",
        "label": "Khoảng cách thử lại gói/Agent (giây)", "help": "Khoảng cách thử lại khi tra cứu gói và tạo Agent Token, tăng theo số lần thử; ưu tiên Retry-After của server",
    },
    {
        "key": "PLAN_CHECK_REGISTRATION_RECHECK_DELAY", "file": "proxy.py", "type": "float", "group": "Kho proxy",
        "label": "Độ trễ kiểm tra lại quyền tài khoản mới (giây)", "help": "Tài khoản free mới đăng ký chưa thấy quyền dùng thử hoặc lần tra cứu đầu thất bại thì kiểm tra lại một lần; 0 là tắt",
    },
    {
        "key": "PLAN_CHECK_WORKERS", "file": "proxy.py", "type": "int", "group": "Kho proxy",
        "label": "Số luồng tra cứu gói", "help": "Tự động, thủ công và tra cứu gói hàng loạt dùng chung; tạo Agent Token dùng hàng đợi riêng; nên 2-4 luồng",
    },
    {
        "key": "PLAN_CHECK_QUEUE_LIMIT", "file": "proxy.py", "type": "int", "group": "Kho proxy",
        "label": "Trần hàng đợi tra cứu gói", "help": "Chặn thao tác hàng loạt lỗi chồng vô hạn, nên 100-1000",
    },
    {
        "key": "PLAN_CHECK_MIN_INTERVAL", "file": "proxy.py", "type": "float", "group": "Kho proxy",
        "label": "Khoảng cách tối thiểu request gói/Agent (giây)", "help": "Giới hạn tần suất bắt đầu request tra cứu gói và tạo Agent Token, giảm rủi ro 429",
    },
    {
        "key": "PLAN_CHECK_JITTER", "file": "proxy.py", "type": "float", "group": "Kho proxy",
        "label": "Độ lệch ngẫu nhiên request gói/Agent (giây)", "help": "Thêm độ trễ ngẫu nhiên vào khoảng cách tối thiểu của tra cứu gói và tạo Agent Token, tránh request quá đều",
    },
    # ---- Trích xuất liên kết ----
    {
        "key": "EXTRACT_LINK_API_BASE", "file": "extract_link.py", "type": "str", "group": "Rút link",
        "label": "Địa chỉ dịch vụ rút link", "help": "Điền địa chỉ API dịch vụ rút link",
    },
    {
        "key": "EXTRACT_LINK_CDK", "file": "extract_link.py", "type": "str", "group": "Rút link",
        "label": "CDK rút link", "help": "Dùng khi tạo tác vụ rút link và theo dõi sự kiện; rút link thành công trừ 1 lượt",
        "storage": "env", "secret": True,
    },
    {
        "key": "EXTRACT_LINK_TYPE", "file": "extract_link.py", "type": "str", "group": "Rút link",
        "label": "Loại rút link", "help": "Hỗ trợ pix / upi / kakao_pay / ideal",
    },
    {
        "key": "EXTRACT_LINK_WORKERS", "file": "extract_link.py", "type": "int", "group": "Rút link",
        "label": "Số luồng rút link", "help": "Số luồng nền rút link hàng loạt, nên 1-4",
    },
    # ---- Cấu hình Codex ----
    {
        "key": "SUB2API_AUTO_EXPORT", "file": "sub2api.py", "type": "bool", "group": "Codex",
        "label": "Tự đồng bộ Agent sub2", "help": "Sau khi tạo Codex Agent Token thành công, tự đồng bộ sang sub2api",
    },
    {
        "key": "SUB2API_SYNC_MODE", "file": "sub2api.py", "type": "str", "group": "Codex",
        "label": "Chế độ đồng bộ Agent sub2", "help": "api=tải lên API trực tiếp; file=ghi json local; both=API + json local",
    },
    {
        "key": "SUB2API_API_BASE", "file": "sub2api.py", "type": "str", "group": "Codex",
        "label": "Base URL sub2 API", "help": "Địa chỉ dịch vụ sub2api; Agent Token tải lên và Codex OAuth dùng chung, ví dụ http://127.0.0.1:8080",
    },
    {
        "key": "SUB2API_API_KEY", "file": "sub2api.py", "type": "str", "group": "Codex",
        "label": "sub2 API Key", "help": "API Key giao diện quản trị sub2api; header dùng x-api-key; để trống thì không gửi header xác thực", "storage": "env", "secret": True,
    },
    {
        "key": "SUB2API_API_TIMEOUT", "file": "sub2api.py", "type": "int", "group": "Codex",
        "label": "Timeout sub2", "help": "Số giây timeout request sub2api",
    },
    {
        "key": "SUB2API_OUTPUT_PATH", "file": "sub2api.py", "type": "str", "group": "Codex",
        "label": "Đường dẫn local Agent sub2", "help": "Chỉ dùng khi SUB2API_SYNC_MODE=file/both; đường dẫn tương đối giải theo thư mục gốc dự án",
    },
    {
        "key": "SUB2API_PROXY_KEY", "file": "sub2api.py", "type": "str", "group": "Codex",
        "label": "Khoá proxy Agent sub2", "help": "Tuỳ chọn; ghi vào account.proxy_key, và khởi tạo proxies[0].proxy_key khi proxies trống",
    },
    # ---- Nền tảng nhận mã ----
    # ---- Codex: cấu hình cơ bản / CPA / sub2api ----
    {
        "key": "CODEX_AUTH_URL_SOURCE", "file": "codex.py", "type": "str", "group": "Codex",
        "label": "Nguồn URL uỷ quyền", "help": "cpa=CPA tạo và tải lên CPA; sub2=sub2 tạo và tải lên sub2; local=PKCE local",
    },
    {
        "key": "CPA_MANAGEMENT_URL", "file": "codex.py", "type": "str", "group": "Codex",
        "label": "Địa chỉ quản trị CPA", "help": "Ví dụ http://localhost:8317/admin/oauth; chương trình lấy origin rồi gọi /v0/management/*",
    },
    {
        "key": "CPA_MANAGEMENT_KEY", "file": "codex.py", "type": "str", "group": "Codex",
        "label": "Khoá quản trị", "help": "Lưu trong .env (CPA_MANAGEMENT_KEY), không ghi lại config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "CPA_REQUEST_TIMEOUT", "file": "codex.py", "type": "int", "group": "Codex",
        "label": "Timeout CPA (giây)", "help": "Timeout request API quản trị CPA",
    },
    {
        "key": "CPA_SAVE_CALLBACK_RECEIPT", "file": "codex.py", "type": "bool", "group": "Codex",
        "label": "Lưu biên nhận CPA", "help": "Khi CPA không trả file uỷ quyền đầy đủ, vẫn lưu local một bản ghi đã gửi callback",
    },

    {
        "key": "SMS_PROVIDER", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Kênh nhận OTP", "help": "grizzly / smsbower / l / h; smsbower dùng SMSBower handler_api, l/h dùng dịch vụ lấy số cục bộ",
    },
    {
        "key": "SMS_COUNTRY", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Mã quốc gia", "help": "country gửi nền tảng nhận mã；SMSBower điền theo bảng quốc gia, GrizzlySMS thường Mỹ=187；kênh H là country trong H_API.md",
    },
    {
        "key": "SMS_SERVICE", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Mã dịch vụ/dự án", "help": "GrizzlySMS/L/SMSBower làm service；OpenAI (ChatGPT) của SMSBower nên điền dr, điền openai/chatgpt thì chương trình tự chuyển；kênh H làm projectId",
    },
    {
        "key": "SMS_MAX_PRICE", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Giá số tối đa", "help": "maxPrice truyền thẳng tới nền tảng nhận mã; để trống thì không giới hạn. SMSBower dùng để lọc giá/hạng số",
    },
    {
        "key": "SMS_MAX_RETRIES", "file": "codex.py", "type": "int", "group": "Nền tảng nhận OTP",
        "label": "Số lần đổi số", "help": "Một số không nhận được SMS hoặc bị OpenAI từ chối thì đổi số khác, tối đa bao nhiêu lần",
    },
    {
        "key": "SMS_CODE_WAIT", "file": "codex.py", "type": "int", "group": "Nền tảng nhận OTP",
        "label": "Chờ SMS mỗi số (giây)", "help": "Số giây tối đa chờ SMS của một số, hết giờ thì đổi số",
    },
    {
        "key": "SMS_API_KEY", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Khoá API GrizzlySMS", "help": "API Key nền tảng GrizzlySMS, lưu trong .env (SMS_API_KEY), không ghi lại config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "SMSBOWER_API_BASE", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Địa chỉ SMSBower API", "help": "Mặc định https://smsbower.page/stubs/handler_api.php",
    },
    {
        "key": "SMSBOWER_API_KEY", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Khoá API SMSBower", "help": "API Key console SMSBower, lưu trong .env, không ghi lại config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "SMSBOWER_USE_V2", "file": "codex.py", "type": "bool", "group": "Nền tảng nhận OTP",
        "label": "SMSBower dùng lấy số V2", "help": "Tài liệu client chính thức dùng getNumber; thường giữ tắt. Chỉ bật khi xác nhận tài khoản hỗ trợ getNumberV2",
    },
    {
        "key": "SMSBOWER_PROVIDER_IDS", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Lọc nhà cung cấp SMSBower", "help": "Tuỳ chọn, ID nhà cung cấp cách nhau bằng dấu phẩy; để trống thì nền tảng tự chọn",
    },
    {
        "key": "SMSBOWER_EXCEPT_PROVIDER_IDS", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Loại trừ nhà cung cấp SMSBower", "help": "Tuỳ chọn, ID nhà cung cấp loại trừ cách nhau bằng dấu phẩy",
    },
    {
        "key": "SMSBOWER_PHONE_EXCEPTION", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Tiền tố số SMSBower loại trừ", "help": "Tuỳ chọn, tiền tố số cách nhau bằng dấu phẩy; dùng để tránh đầu số đã biết không dùng được",
    },
    {
        "key": "SMSBOWER_MIN_PRICE", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Giá tối thiểu SMSBower", "help": "Tuỳ chọn, truyền thẳng minPrice; cùng giá cao nhất để giới hạn khoảng giá số",
    },
    {
        "key": "H_API_BASE", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Địa chỉ H API", "help": "Địa chỉ gốc dịch vụ lấy số H, ví dụ http://localhost:8788",
    },
    {
        "key": "H_ADMIN_AUTH_CODE", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Mã uỷ quyền H", "help": "Lưu trong .env (H_ADMIN_AUTH_CODE), không ghi lại config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "H_PHONE_PREFIX", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Tiền tố số H", "help": "Điền khi số H trả về không có mã quốc gia, ví dụ số local Mỹ 10 số thì điền 1; để trống thì không thêm",
    },
    {
        "key": "H_PHONE_ACQUIRE_MODE", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Cách lấy số H", "help": "reusable=ưu tiên dùng lại số còn dùng được; new=mỗi lần lấy một số mới",
    },
    {
        "key": "L_API_BASE", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Địa chỉ L API", "help": "Địa chỉ gốc dịch vụ lấy số L, ví dụ http://localhost:8788",
    },
    {
        "key": "L_ADMIN_AUTH_CODE", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Mã uỷ quyền L", "help": "Lưu trong .env (L_ADMIN_AUTH_CODE), không ghi lại config/*.py",
        "storage": "env", "secret": True,
    },
    {
        "key": "L_PHONE_PREFIX", "file": "codex.py", "type": "str", "group": "Nền tảng nhận OTP",
        "label": "Tiền tố số L", "help": "Điền khi số L trả về không có mã quốc gia, ví dụ số local Mỹ 10 số thì điền 1; để trống thì không thêm",
    },
]

_FIELD_BY_KEY = {f["key"]: f for f in EDITABLE_FIELDS}


# ============================================================
# Đọc: phân tích mã nguồn lấy giá trị hiện tại (không import, tránh cache/tác dụng phụ)
# ============================================================

def _config_path(filename: str) -> Path:
    path = (_CONFIG_DIR / filename).resolve()
    # Chống directory traversal: phải nằm trong config/
    if _CONFIG_DIR not in path.parents:
        raise ValueError(f"Đường dẫn cấu hình không hợp lệ: {filename}")
    return path


def _literal_default_from_expr(node):
    """Cố gắng lấy “giá trị mặc định trong mã nguồn” từ biểu thức gán, không thực thi mã module.

    Tương thích:
      KEY = "literal"
      KEY: str = env_str("KEY", "default")
      KEY = env_bool("KEY", True)
      KEY = env_value("KEY", 123, "int")
    """
    try:
        return ast.literal_eval(node)
    except Exception:
        pass

    if isinstance(node, ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # Tham số vị trí thứ hai của env_str/env_bool/env_int/env_float/env_list là giá trị mặc định.
        if func_name in {"env_str", "env_bool", "env_int", "env_float", "env_list"}:
            if len(node.args) >= 2:
                try:
                    return ast.literal_eval(node.args[1])
                except Exception:
                    return None
            return None

        # env_value(key, default, vtype)
        if func_name == "env_value" and len(node.args) >= 2:
            try:
                return ast.literal_eval(node.args[1])
            except Exception:
                return None

    return None


def _find_assignment_value_node(source: str, key: str):
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for t in targets:
            if isinstance(t, ast.Name) and t.id == key:
                return node.value
    return None


def _parse_value_from_source(source: str, key: str, vtype: str):
    """Phân tích giá trị hiện tại của KEY từ mã nguồn. Thất bại trả về None."""
    if vtype == "list_str_multiline":
        # Dùng AST phân tích toàn bộ module, lấy list literal của phép gán này
        value_node = _find_assignment_value_node(source, key)
        if value_node is None:
            return None
        try:
            val = ast.literal_eval(value_node)
            if isinstance(val, (list, tuple)):
                return [str(x) for x in val]
        except (ValueError, SyntaxError):
            return None
        return None

    # Scalar: ưu tiên AST lấy giá trị mặc định, tránh env_str("KEY", "") bị coi là chuỗi thường.
    value_node = _find_assignment_value_node(source, key)
    if value_node is not None:
        value = _literal_default_from_expr(value_node)
        if value is not None:
            return value

    # Khi AST thất bại thì fallback về phân tích regex cũ.
    m = re.search(
        rf"^{re.escape(key)}\s*(?::[^=\n]+)?=\s*(.+?)\s*(?:#.*)?$",
        source, re.MULTILINE,
    )
    if not m:
        return None
    raw = m.group(1).strip()
    try:
        return ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        return raw


def _parse_env_typed_value(raw: str, fallback, vtype: str):
    """Chuyển chuỗi .env theo kiểu trường; khi thất bại thì fallback."""
    from config.env_loader import env_value
    return env_value("__NO_SUCH_ENV_KEY__", fallback, vtype) if raw is None else _coerce_raw_value(raw, fallback, vtype)


def _coerce_raw_value(raw: str, fallback, vtype: str):
    try:
        if raw is None or str(raw).strip() == "":
            return fallback
        if vtype == "bool":
            return str(raw).strip().lower() in ("true", "1", "yes", "on", "y")
        if vtype == "int":
            return int(str(raw).strip())
        if vtype == "float":
            return float(str(raw).strip())
        if vtype == "list_str_multiline":
            text = str(raw)
            try:
                val = ast.literal_eval(text)
                if isinstance(val, (list, tuple)):
                    return [str(x).strip() for x in val if str(x).strip()]
            except Exception:
                pass
            return [line.strip() for line in text.splitlines() if line.strip()]
        return str(raw)
    except Exception:
        return fallback


def get_config() -> list[dict]:
    """Trả về giá trị hiện tại + siêu thông tin của tất cả mục có thể chỉnh sửa, để frontend render form.

    Ưu tiên đọc `.env` / biến môi trường; khi chưa cấu hình thì fallback về giá trị mặc định `config/*.py`.
    """
    from config.env_loader import load_env, read_env_file
    load_env(override=True)
    env_file_values = read_env_file()

    out = []
    for field in EDITABLE_FIELDS:
        key = field["key"]
        path = _config_path(field["file"])
        source = path.read_text(encoding="utf-8") if path.exists() else ""
        fallback = _parse_value_from_source(source, key, field["type"])

        if key in env_file_values:
            raw_env_value = env_file_values[key]
            if field["type"] == "list_str_multiline" and key in EXPLICIT_EMPTY_LIST_KEYS and str(raw_env_value).strip() == "":
                value = []
            else:
                value = _coerce_raw_value(raw_env_value, fallback, field["type"])
        elif os.getenv(key) is not None:
            value = _coerce_raw_value(os.getenv(key, ""), fallback, field["type"])
        else:
            value = fallback

        if field["type"] in ("str", "list_str_multiline"):
            value = _normalize_config_value(value, field["type"])
        item = dict(field)
        item["storage"] = "env"
        item["value"] = value
        out.append(item)
    return out


# ============================================================
# Ghi: thống nhất ghi .env, không sửa config/*.py
# ============================================================


_PLACEHOLDER_EMPTY = {
    "", "-", "—", "无", "空", "none", "null", "n/a", "na", "未设置", "未配置", "Chưa đặt", "Chưa cấu hình", "Không", "Trống",
}


def _normalize_config_value(value, vtype: str):
    """Chuẩn hóa giá trị trống placeholder của frontend/lịch sử, tránh coi '-' là cấu hình thật."""
    if vtype == "str":
        s = "" if value is None else str(value).strip()
        if s.lower() in {x.lower() for x in _PLACEHOLDER_EMPTY}:
            return ""
        return s
    if vtype == "list_str_multiline":
        if value is None:
            return []
        if isinstance(value, str):
            lines = value.splitlines()
        elif isinstance(value, (list, tuple)):
            lines = list(value)
        else:
            lines = [str(value)]
        out = []
        for item in lines:
            s = str(item or "").strip()
            if not s or s.lower() in {x.lower() for x in _PLACEHOLDER_EMPTY}:
                continue
            out.append(s)
        return out
    return value


def _format_literal(value, vtype: str) -> str:
    """Định dạng giá trị từ frontend thành chuỗi literal Python."""
    if vtype == "bool":
        if isinstance(value, str):
            value = value.strip().lower() in ("true", "1", "yes", "on")
        return "True" if value else "False"
    if vtype == "int":
        return str(int(value))
    if vtype == "float":
        return repr(float(value))
    if vtype == "str":
        s = str(value)
        # Dùng repr đảm bảo an toàn escape, nhưng thống nhất theo kiểu dấu ngoặc kép
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    raise ValueError(f"_format_literal không hỗ trợ kiểu: {vtype}")


def _replace_scalar(source: str, key: str, literal: str) -> str:
    """Thay thế vế phải của dòng `KEY[: loại] = giá trị cũ`, giữ nguyên chú thích trong dòng và chú thích kiểu."""
    pattern = re.compile(
        rf"^(?P<head>{re.escape(key)}\s*(?::[^=\n]+)?=\s*)"
        rf"(?P<val>.+?)"
        rf"(?P<tail>\s*(?:#.*)?)$",
        re.MULTILINE,
    )
    if not pattern.search(source):
        raise ValueError(f"Không tìm thấy phép gán có thể thay trong mã nguồn: {key}")
    return pattern.sub(lambda m: f"{m.group('head')}{literal}{m.group('tail')}", source, count=1)


def _replace_proxy_pool(source: str, lines: list[str]) -> str:
    """Thay thế toàn bộ literal danh sách PROXY_POOL = [ ... ] (giữ nguyên phần đầu gán phía trước)."""
    items = [ln.strip() for ln in lines if ln.strip()]
    if items:
        body = "\n".join(
            '    "' + it.replace("\\", "\\\\").replace('"', '\\"') + '",'
            for it in items
        )
        literal = "[\n" + body + "\n]"
    else:
        literal = "[]"

    # Khớp PROXY_POOL = [ ... ] (bao gồm nhiều dòng), dùng AST định vị offset bắt đầu/kết thúc là ổn định nhất
    tree = ast.parse(source)
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else (
            [node.target] if isinstance(node, ast.AnnAssign) else []
        )
        for t in targets:
            if isinstance(t, ast.Name) and t.id == "PROXY_POOL":
                src_lines = source.splitlines(keepends=True)
                start = node.value.lineno          # Dòng chứa giá trị ([), 1-based
                end = node.value.end_lineno        # Dòng chứa giá trị (]), 1-based
                col = node.value.col_offset         # Offset cột của [ trên dòng bắt đầu
                # Giữ nội dung trước [ trên dòng bắt đầu (tức "PROXY_POOL = " hoặc "PROXY_POOL: list = ")
                prefix = src_lines[start - 1][:col]
                # Giữ nội dung sau ] trên dòng kết thúc (chú thích trong dòng / xuống dòng)
                end_line = src_lines[end - 1]
                suffix = end_line[node.value.end_col_offset:]
                new_lines = (
                    src_lines[: start - 1]
                    + [prefix + literal + suffix]
                    + src_lines[end:]
                )
                return "".join(new_lines)
    raise ValueError("Không tìm thấy phép gán PROXY_POOL")


def _atomic_write(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def _format_env_value(value, vtype: str, fallback=None) -> str:
    """Định dạng giá trị frontend thành chuỗi phù hợp để ghi vào .env."""
    if value is None:
        value = fallback
    if vtype == "bool":
        if isinstance(value, str):
            value = value.strip().lower() in ("true", "1", "yes", "on", "y")
        return "True" if value else "False"
    if vtype == "int":
        try:
            return str(int(value))
        except (TypeError, ValueError):
            return str(int(fallback)) if fallback is not None else "0"
    if vtype == "float":
        try:
            return repr(float(value))
        except (TypeError, ValueError):
            return repr(float(fallback)) if fallback is not None else "0.0"
    if vtype == "list_str_multiline":
        lines = _normalize_config_value(value, vtype)
        return "\n".join(lines) if lines else "[]"
    if vtype == "str":
        return _normalize_config_value(value, vtype)
    return "" if value is None else str(value)


def update_config(updates: dict) -> dict:
    """Cập nhật cấu hình hàng loạt. Mọi mục WebUI chỉnh được chỉ ghi vào `.env` gốc dự án."""
    from config.env_loader import write_env_values, load_env

    updated, ignored = [], []
    env_updates: dict[str, str] = {}
    current_values = {
        item["key"]: item.get("value")
        for item in get_config()
    }

    for key, value in updates.items():
        field = _FIELD_BY_KEY.get(key)
        if field is None:
            ignored.append(key)
            continue
        choices = field.get("choices") or []
        if choices:
            allowed = {str(item.get("value")) for item in choices}
            if str(value) not in allowed:
                raise ValueError(f"{key} có giá trị không hợp lệ, chọn:{', '.join(sorted(allowed))}")
        env_updates[key] = _format_env_value(
            value,
            field["type"],
            fallback=current_values.get(key),
        )
        updated.append(key)


    env_updated = write_env_values(env_updates) if env_updates else []
    if env_updated:
        load_env(override=True)

    return {"updated": updated, "ignored": ignored, "env_updated": env_updated}

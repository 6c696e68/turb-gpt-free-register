# Turb GPT Free Register

Bản cài local để **nghiên cứu** luồng đăng ký ChatGPT / OpenAI và uỷ quyền Codex OAuth. Repo này không merge vào gpt-tool, không publish, không đẩy upstream trừ khi được yêu cầu.

Công cụ hỗ trợ năm driver đăng ký:

- **protocol**: đăng ký thuần giao thức, dựa trên `curl_cffi` + Sentinel/PoW.
- **roxy**: RoxyBrowser fingerprint + Selenium. Tương thích luồng trang mới, ví dụ `create-account/password`, form tuổi/ngày sinh `about-you`, trang theo locale.
- **cloak**: CloakBrowser + lớp thích ứng Playwright. Hỗ trợ binary miễn phí, headless, humanize, fingerprint seed cố định, geoip theo proxy.
- **browser_use**: Browser Use Cloud stealth Chromium + Playwright (proxy residential tuỳ chọn, không cần cài Roxy trên máy).
- **skyvern**: Skyvern Browser Sessions (trình duyệt cloud) + Playwright CDP.

Có **CLI** và **WebUI local**. Research hằng ngày nên dùng WebUI để xem log và đổi cấu hình nóng.

> Nguồn: fork/mở rộng từ [xiaoguzuiniu/gpt-free-register](https://github.com/xiaoguzuiniu/gpt-free-register).

- Nhóm TG: [https://t.me/+uC3Ix0l2E085Njhl](https://t.me/+uC3Ix0l2E085Njhl)

> Bản nguồn mở chỉ giữ mã, template cấu hình và tài liệu. Tài khoản runtime, Token, kho email, credential Codex, nhật ký đều bị `.gitignore` loại trừ.

---

## Lời cảm ơn

[![IPWO residential proxy](https://raw.githubusercontent.com/myfanhua/turb-gpt-free-register/main/static/telegram-cloud-photo-size-5-6154589162401632962-y.jpg)](https://www.ipwo.net/?code=XEP358YGZ)

IPWO cung cấp IP residential phủ 195+ quốc gia/vùng, cấu hình mạng đa vùng, dùng cho ứng dụng AI, tự động hoá trình duyệt, truy cập dịch vụ nước ngoài và thu thập dữ liệu.
Lưu ý nhà tài trợ: 2GB traffic residential động không điều kiện, [cổng nhận](https://www.ipwo.net/?code=XEP358YGZ); nhóm TG thỉnh thoảng phát IP.

## Tổng quan tính năng

### Đăng ký

- Đăng ký hàng loạt tài khoản ChatGPT.
- Đổi driver đăng ký:
  - `REGISTRATION_DRIVER = "protocol"`
  - `REGISTRATION_DRIVER = "roxy"`
  - `REGISTRATION_DRIVER = "cloak"`
  - `REGISTRATION_DRIVER = "browser_use"`
  - `REGISTRATION_DRIVER = "skyvern"`
- RoxyBrowser một tài khoản một profile: tự tạo, mở, đóng, xoá Roxy Profile.
- Roxy headless: `ROXY_OPEN_HEADLESS=True`.
- CloakBrowser: binary miễn phí, headless, humanize, fingerprint seed cố định, tự khớp ngôn ngữ/múi giờ/WebRTC theo IP đầu ra.
- Đăng ký trình duyệt Roxy / Cloak đã xử lý:
  - Sau khi điền email, vào thẳng trang mã OTP email;
  - Sau khi điền email, vào `create-account/password`, tự đặt mật khẩu rồi tiếp tục;
  - Trang `about-you/profile` nhập thẳng số tuổi;
  - Trang `about-you/profile` nhập ngày/tháng/năm;
  - Control React Aria birthday select / spinbutton;
  - Thứ tự nút đổi theo IP đầu ra / ngôn ngữ trang, tránh bấm nhầm đăng nhập bên thứ ba.

### Nguồn email

Hỗ trợ nhiều nguồn:

- Kho email Outlook: `email----password----clientId----refreshToken`
- Email domain Cloudflare + nhận thư QQ IMAP (`cloudflare_domain`)
- Email tạm Cloudflare Worker: tự tạo + lấy mã bằng JWT (`cloudflare`, tương thích cloudflare_temp_email)
- Email API chung: `email----URL lấy mã`
- Kho IMAP chung: mỗi dòng `email----mật khẩu IMAP` hoặc `email:mật khẩu IMAP`; server, cổng và SSL cấu hình chung lúc nhập
- API email tạm GPTMail: lúc chạy sinh email ngẫu nhiên và tự nhận mã OTP
- Remail Open API: đặt email ngắn hạn theo dự án và tự nhận mã OTP (`remail`)
- `EMAIL_SOURCE` ghép nhiều nguồn, ví dụ:

```python
EMAIL_SOURCE = "outlook,generic_api,imap"
```

- MailNest: email tạm Outlook

### Codex OAuth

- Sau đăng ký thành công có thể tự chạy Codex OAuth.
- Driver uỷ quyền Codex:
  - `CODEX_OAUTH_DRIVER = "protocol"`
  - `CODEX_OAUTH_DRIVER = "roxy"`
  - `CODEX_OAUTH_DRIVER = "cloak"`
  - `CODEX_OAUTH_DRIVER = "browser_use"`
  - `CODEX_OAUTH_DRIVER = "same_as_registration"`
- CPA management API tạo URL uỷ quyền và nộp OAuth callback.
- Nền tảng nhận OTP SMS:
  - GrizzlySMS
  - Dịch vụ lấy số L local, xem `L_API.md`
- Xác minh điện thoại: tự lấy số, điền số, nhận mã, gửi, thất bại thì đổi số và thử lại.
- Credential Codex lưu bảng SQLite `codex_accounts`.

### WebUI

- Khởi chạy tác vụ đăng ký hàng loạt.
- Xem nhật ký tác vụ realtime.
- Đổi số luồng đăng ký; tác vụ mới dùng giá trị mới ngay sau khi gửi.
- Bổ chạy Codex hàng loạt; số luồng bổ chạy có hiệu lực ngay mỗi lần gửi.
- Quản lý tài khoản, kho email, credential Codex. Trang tài khoản hỗ trợ đổi email đơn/hàng loạt và chọn nguồn email mới; sau đổi email hiện cả email gốc và email hiện tại, xem nhật ký đổi email, và tự kiểm tra sống để làm mới AT.
- Nhập kho email mặc định không tạo tài khoản. Tick “coi là tài khoản đăng ký thành công sau khi nhập” sẽ đánh dấu kho email đã dùng và hiện ở trang tài khoản, để bổ chạy Codex hàng loạt.
- Sau đăng ký Roxy/Cloak, thống kê upload, download và tổng lưu lượng của cả phiên trình duyệt; danh sách tác vụ và thông tin mở rộng tài khoản đều lưu kết quả. Browser Use/Skyvern là trình duyệt cloud, không bật lắng nghe lưu lượng local, chặn tài nguyên hay thu JS coverage.
- Trang cấu hình hot-reload; lưu xong không cần restart.
- Team/dự án Roxy lấy và lưu ngay trên trang cấu hình.

### Lưu trữ dữ liệu

- Tài khoản, kho email, tác vụ và credential Codex runtime nằm ở `turb.sqlite3` gốc repo, tách thành năm bảng: `accounts`, `email_pool`, `registration_jobs`, `codex_accounts`, `codex_agent_accounts`.
- DB bật WAL, timeout chờ và index field thường dùng. Phân trang tài khoản, trạng thái gói, kho email, Codex và tác vụ trên WebUI chạy thẳng SQLite `COUNT(*) + LIMIT/OFFSET`, không đọc full rồi cắt bằng Python.
- Lần chạy đầu tự migrate JSON/SQLite cũ sang DB mới. Sau migrate không đọc/ghi file JSON/TXT tài khoản, tác vụ, kho email và credential Codex.
- `turb.sqlite3*` là dữ liệu runtime, đã vào `.gitignore`; hãy đưa vào chiến lược backup.

### Thống kê lưu lượng mạng trình duyệt

Driver trình duyệt thống kê từ lúc mở trang đăng ký đến khi hết thời gian dừng sau đăng ký, trước khi đóng trình duyệt. Kết quả gồm:

- Byte upload, byte download, tổng byte;
- Số request HTTP, số request thất bại/chưa xong;
- Byte payload frame WebSocket (nếu luồng dùng WebSocket).

Danh sách tác vụ đăng ký trên WebUI hiện đại/Legacy hiện tổng lưu lượng. Cấu trúc đầy đủ nằm ở `network_traffic` của bản ghi tác vụ và `extra_json` của tài khoản thành công. Thống kê là lưu lượng request/response quan sát được phía trình duyệt, không gồm overhead TLS/IP/tunnel proxy, cũng không gồm lưu lượng email API, Roxy API hay kênh điều khiển CDP.

#### Chế độ tiết kiệm data

Bật «Chế độ tiết kiệm data trình duyệt local» trong WebUI «Hồ sơ trình duyệt», hoặc đặt trong `.env` (chỉ Roxy/Cloak):

```dotenv
BROWSER_DATA_SAVER_MODE=True
BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES=["image", "media"]
# Danh sách URL glob; trên WebUI thì một dòng một mục
BROWSER_DATA_SAVER_BLOCKED_URL_PATTERNS='["**://auth.openai.com/awe/api/v2/rum**", "**://chatgpt.com/awe/api/v2/rum**", "**://chatgpt.com/ces/statsc/flush**", "**://connect.facebook.net/**", "**://analytics.tiktok.com/**", "**://snap.licdn.com/**", "**://bat.bing.com/**", "**://accounts.google.com/gsi/client**"]'
```

Roxy/Selenium tắt tải ảnh trong tham số khởi động, và dùng Chrome CDP chặn hậu tố URL ảnh/media phổ biến cùng URL glob đã cấu hình (nên cũng phủ tài nguyên không có extension). Cloak dùng Playwright chặn theo loại tài nguyên và URL glob. Browser Use/Skyvern là trình duyệt cloud, không cài interceptor tiết kiệm data local, luôn giữ đủ tài nguyên trang. Mặc định chỉ chặn `image`, `media`, và URL thống kê RUM/quảng cáo trong cấu hình; không chặn theo loại script lõi, API và WebSocket cần cho đăng nhập. Playwright cho qua URL có từ khoá mã OTP/challenge. Công tắc ảnh Chromium và blacklist URL CDP của Roxy không có ngoại lệ theo URL; nếu trang hiện captcha hoặc layout lỗi, tắt chế độ rồi thử lại.

Chi tiết Job 208: rule hiện tại thực tế chặn 5 script bên thứ ba (Google GSI, Facebook, TikTok, LinkedIn, Bing) và 380 request RUM; đăng ký email/mật khẩu thành công. Phía đăng ký download khoảng 9.92 MiB, trong đó script khoảng 8.90 MiB, chủ yếu từ CDN chunk lõi ChatGPT.

Rule mặc định hiện chỉ gồm thống kê RUM/quảng cáo và Google GSI. Đăng ký email/mật khẩu không dùng đăng nhập Google, nên giữ rule GSI. Nếu sau này bật đăng nhập Google, xoá dòng sau khỏi «Quy tắc chặn URL tiết kiệm data»:

```text
**://accounts.google.com/gsi/client**
```

`**://chatgpt.com/ces/v1/rgstr` nghi là telemetry CES, khoảng 277 KiB/vòng; có thể thêm sau khi xác minh riêng tỷ lệ đăng ký thành công.

Đừng chặn `chatgpt.com/cdn/assets/*.js`, `auth-cdn.oaistatic.com/assets/*.js`, `sentinel.openai.com`, `chatgpt.com/backend-api/sentinel/*`, `ab.chatgpt.com/v1/initialize`, `chatgpt.com/realtime/wm` và API đăng ký/OTP/session. Job 207 chặn `7aaae702-*.js` rồi mất ô nhập OTP; Job 208 cho chunk đó qua thì thành công đầy đủ. Không được chặn CDN chunk chỉ vì tỷ lệ hàm thực thi thấp. Điền `[]` vào rule URL để chỉ chặn theo loại tài nguyên; để trống thì dùng rule mặc định tích hợp.

Muốn chặn CSS thì thêm `stylesheet`:

```dotenv
BROWSER_DATA_SAVER_BLOCKED_RESOURCE_TYPES=["image", "media", "stylesheet"]
```

CSS thường không bắt buộc cho API đăng ký, nhưng ảnh hưởng phần tử ẩn, layout và phán đoán visibility. Nên test riêng; nếu không tìm thấy phần tử hoặc click lỗi thì bỏ `stylesheet`.

#### Nhật ký chi tiết tài nguyên

Khi cần phân tích tài nguyên nào chiếm lưu lượng trong luồng đăng ký, bật:

```dotenv
BROWSER_TRAFFIC_DETAIL_LOG=True
BROWSER_TRAFFIC_DETAIL_MAX_ENTRIES=2000
```

Sau tác vụ đăng ký Roxy/Cloak đã bật thống kê, log in dòng `[资源明细]`: URL, loại, method HTTP, status, kích thước upload/download, kích thước body/header response, và trạng thái `failed`, `blocked`, `unfinished`, `cache`. Chi tiết sắp theo tổng byte mỗi request giảm dần. Browser Use/Skyvern không bật listener này. `ws_upload/ws_download` là payload frame WebSocket. Trạng thái cache Playwright hiện `unknown` khi API không xác nhận được; Selenium/CDP nhận ra thì hiện `hit` hoặc `miss`. Giá trị query của URL và nội dung data/blob URL không ghi log.

Tag log `[资源明细]` là literal code, không đổi. Gửi log một vòng đăng ký rồi đối chiếu domain, path, loại tài nguyên và byte thực để quyết định có chặn tiếp không. `stylesheet`, `font` chỉ bật sau khi xem đăng ký có bị ảnh hưởng không.

#### Độ phủ hàm JS đã thực thi

Khi cần xác nhận một CDN chunk có thực sự chạy trong luồng đăng ký Roxy/Cloak, bật:

```dotenv
BROWSER_JS_COVERAGE_LOG=True
BROWSER_JS_COVERAGE_MAX_ENTRIES=1000
```

Roxy/Selenium bật CDP `Profiler.startPreciseCoverage` trên Chrome target hiện tại. Cloak mở CDP session cho Chromium Page đã phát hiện. Browser Use/Skyvern không bật JS coverage. Cuối tác vụ, log có `[JS执行汇总]`, `[JS脚本]` mỗi script, `[JS执行]` của hàm thực sự chạy (tên hàm, số lần gọi, `startOffset-endOffset:count`), và `[JS候选]` cho “vòng này không quan sát thấy vùng thực thi”. `network_traffic.js_coverage` lưu tóm tắt cấp script và URL ứng viên; offset từng hàm chỉ ghi log, không lưu source, tham số hay giá trị trả về. Các tag `[JS执行汇总]` / `[JS脚本]` / `[JS执行]` / `[JS候选]` là literal code.

`[JS候选]` chỉ nghĩa là vòng coverage đó không thấy code chạy, không đủ để chứng minh được chặn. Lấy một vòng đăng ký thành công chưa chặn script lõi làm baseline, rồi mỗi lần chỉ chặn một ứng viên và so OTP, session, trang hồ sơ và tỷ lệ thành công. Script từ `data:` / `blob:` / trang extension không đưa vào ứng viên chặn URL. Trang Selenium nhiều popup/target chỉ phủ CDP target hiện tại. Nếu fingerprint browser không hỗ trợ CDP Profiler, log đánh `supported=False` và không ảnh hưởng luồng đăng ký.

---

## Yêu cầu môi trường

- Python 3.10+
- Node.js 18+
- Proxy dùng được, proxy hệ thống/VPN, hoặc môi trường proxy RoxyBrowser
- Nếu đăng ký bằng Roxy: API RoxyBrowser trên máy phải truy cập được
- Nếu đăng ký bằng Cloak: lần chạy đầu tự tải Cloak Chromium binary; `CLOAK_GEOIP=True` cần dependency `cloakbrowser[geoip]`
- Nếu bật uỷ quyền Codex tự động: cần cấu hình nền tảng nhận OTP SMS

Cài dependency:

```bash
# Nên dùng venv của project, đừng dùng pip hệ thống
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
node --version
```

Khi khởi chạy WebUI, `webui.sh` ưu tiên `.venv/bin/python`:

```bash
./webui.sh start
```

Nếu macOS nâng cấp hoặc gỡ Python đã dùng để tạo venv, symlink Python trong `.venv` cũ có thể gãy. Tạo lại bằng Python đang cài:

```bash
rm -rf .venv
python3.12 -m venv .venv   # hoặc Python 3.10+ đang cài
.venv/bin/python -m pip install -r requirements.txt
./webui.sh start
```

Kiểm tra interpreter và Flask mà WebUI đang dùng:

```bash
.venv/bin/python -c 'import sys, flask; print(sys.executable); print(flask.__version__)'
```

### Cấu hình khoá (.env)

API Key quan trọng để ở `.env` gốc project, đừng ghi vào `config/*.py`.

```bash
cp .env.example .env
# Sửa .env, ví dụ:
# BROWSER_USE_API_KEY=...
# ROXY_API_TOKEN=...
```

Khoá hiện đọc từ `.env`:

- `WEBUI_AUTH_CODE` (mã uỷ quyền đăng nhập WebUI)
- `WEBUI_SESSION_SECRET` (tuỳ chọn, khoá ký Session Cookie)
- `BROWSER_USE_API_KEY`
- `SKYVERN_API_KEY`
- `ROXY_API_TOKEN`
- `QQ_IMAP_PASSWORD`
- `CLOUDFLARE_API_KEY` / `CLOUDFLARE_CUSTOM_AUTH` (khi `EMAIL_SOURCE=cloudflare`)
- `REMAIL_API_KEY` (khi `EMAIL_SOURCE=remail`)
- `CPA_MANAGEMENT_KEY`
- `SMS_API_KEY`
- `L_ADMIN_AUTH_CODE`
- `H_ADMIN_AUTH_CODE`

Trang cấu hình WebUI ghi các field này vào `.env` (không ghi vào source config).

---

## Bắt đầu nhanh

### Mã uỷ quyền WebUI

Sau khi WebUI chạy, mọi trang trừ `/login` và mọi API `/api/*` đều kiểm mã uỷ quyền. Nên cấu hình trong `.env`:

```dotenv
WEBUI_AUTH_CODE=mã-uỷ-quyền-của-bạn
```

Cũng có thể truyền lúc khởi chạy:

```bash
python web.py --auth-code mã-uỷ-quyền-của-bạn
```

Ưu tiên: `--auth-code` > `.env`/biến môi trường. Nếu đều chưa đặt, lúc khởi chạy log sẽ tạo và in mã uỷ quyền tạm của lần này. Gọi API bằng Cookie sau đăng nhập, hoặc `X-Auth-Code: <mã uỷ quyền>` / `Authorization: Bearer <mã uỷ quyền>`.

`WEBUI_SESSION_SECRET` tuỳ chọn. Chưa đặt thì suy ra khoá ký Session ổn định từ mã uỷ quyền cố định. Đổi mã uỷ quyền sẽ làm phiên đăng nhập hiện có hết hiệu lực.

### 1. Cấu hình nguồn email

#### Kho email Outlook

Sao chép file mẫu. Tên file là literal runtime, đừng đổi:

```bash
cp 用于注册的邮箱.txt.example 用于注册的邮箱.txt
```

Mỗi dòng:

```text
email----password----clientId----refreshToken
```

Cũng nhập được trên trang «Kho email» của WebUI.

#### Email API chung

Mỗi dòng:

```text
email----code_url
```

Đặt trong `config/email.py`:

```python
EMAIL_SOURCE = "generic_api"
```

Hoặc nguồn ghép:

```python
EMAIL_SOURCE = "outlook,generic_api,mailnest"
```

#### Email IMAP chung

Ở WebUI «Kho email → Nhập» chọn “email lấy mã IMAP chung”, mỗi dòng:

```text
email----imap_password
email:imap_password
```

- Sau khi chọn loại nhập “email lấy mã IMAP chung”, điền server IMAP, cổng và SSL dùng chung.
- Username IMAP luôn là địa chỉ email đó, không cấu hình thêm.
- Cổng thường là `993`, SSL mặc định bật.
- Ví dụ: `user@example.com----app-password`
- Mặc định đọc `INBOX`, đổi ở «Cấu hình → Email / OTP → IMAP chung».

Đặt nguồn email:

```python
EMAIL_SOURCE = "imap"
```

#### Email tạm GPTMail

Ở WebUI «Cấu hình → Email / OTP» điền `GPTMail API Key`, rồi đặt nguồn:

```python
EMAIL_SOURCE = "gptmail"
```

Hoặc trong `.env` gốc project:

```dotenv
GPTMAIL_API_KEY=GPTMail_API_Key_của_bạn
```

Địa chỉ dịch vụ cố định `https://mail.chatgpt.org.uk`. Chưa điền Key thì tác vụ nhắc điền `GPTMail API Key`, không dùng key test công khai.

#### Email tạm Cloudflare Worker (`cloudflare`)

Tương thích Worker kiểu `cloudflare_temp_email`: lúc đăng ký tự tạo email domain, rồi poll hộp thư bằng JWT để lấy mã OTP OpenAI 6 số.
(Khác scheme `cloudflare_domain` / QQ IMAP bên dưới; đừng trộn identifier.)

```dotenv
EMAIL_SOURCE=cloudflare
CLOUDFLARE_API_BASE=https://domain-api-worker-của-bạn
CLOUDFLARE_API_KEY=ADMIN_PASSWORD_của_bạn
CLOUDFLARE_AUTH_MODE=x-admin-auth
# admin tạo mailbox thường dùng:
# CLOUDFLARE_PATH_ACCOUNTS=/admin/new_address
CLOUDFLARE_DEFAULT_DOMAINS=domain-nhận-thư-của-bạn.com
```

Chế độ ẩn danh: `CLOUDFLARE_AUTH_MODE=none` và để trống Key; path tạo mặc định `/api/new_address`. Nếu Turnstile chặn thì chuyển admin. Field khác xem WebUI «Cấu hình → Email / OTP» hoặc `.env.example`.

#### Email domain Cloudflare (`cloudflare_domain`)

Đặt trong `config/email.py`:

```python
EMAIL_SOURCE = "cloudflare_domain"
EMAIL_DOMAIN = "domain-của-bạn"
QQ_EMAIL = "email-QQ-của-bạn"
QQ_IMAP_PASSWORD = "mã-uỷ-quyền-IMAP-QQ"
```

Cloudflare Email Routing phải forward thư domain sang email QQ. Chế độ này không gọi API tạo Worker; chỉ sinh địa chỉ local và lấy thư qua QQ IMAP.

#### Email tạm Outlook MailNest

Cấu hình API Key và mã dự án `MAIL_NEST_PROJECT_CODE` trên WebUI, hoặc trong file cấu hình.

- Trang lấy `api-key`: https://mailnest.top/account
- Trang lấy mã dự án: https://mailnest.top/buy-email. Mặc định `chatgpt001`, dùng được ngay.

#### Remail Open API

Tài liệu Remail: [https://remail.aishop6.com/docs](https://remail.aishop6.com/docs). Dịch vụ dùng API Key tạo đơn nhận mã ngắn hạn theo dự án. Email và service token đơn trả về được dùng tự động cho lần lấy mã sau.

Điền ở WebUI «Cấu hình → Email / OTP»:

- `REMAIL_API_KEY`: API Key đầu `rk-` tạo ở console Remail;
- `REMAIL_PROJECT_ID`: `projectId` trong danh sách «Dự án» Remail dùng cho mã OTP ChatGPT/OpenAI;
- `REMAIL_EMAIL_SUFFIX`: hậu tố đặt hàng; email Microsoft thường điền `outlook.com`.

Rồi đặt:

```dotenv
USE_EMAIL_SERVICE=True
EMAIL_SOURCE=remail
REMAIL_API_BASE=https://remail.aishop6.com
REMAIL_API_KEY=Remail_API_Key_của_bạn
REMAIL_PROJECT_ID=ID-dự-án
REMAIL_EMAIL_SUFFIX=outlook.com
REMAIL_SERVICE_MODE=purchase
REMAIL_SUPPLY_POLICY=public_only
```

`REMAIL_SERVICE_MODE` mặc định `purchase` (mua dài hạn, nhận thư lặp lại), có thể đổi `code` (nhận mã ngắn hạn).
`REMAIL_SUPPLY_POLICY` mặc định `public_only`, có thể đổi `private_first`. Mỗi tác vụ đăng ký tạo một đơn đúng mode; mã OTP lấy qua `/v1/pickup`. Số dư đơn Remail và tồn kho dự án phải còn.

---

### 2. Cấu hình driver đăng ký

Sửa `config/roxybrowser.py`, hoặc sửa trên trang «Cấu hình» WebUI.

#### Đăng ký bằng RoxyBrowser

```python
REGISTRATION_DRIVER = "roxy"  # protocol / roxy / cloak
ROXY_API_BASE = "http://127.0.0.1:50100"
ROXY_API_TOKEN = "Roxy API Key của bạn"
ROXY_WORKSPACE_ID = "workspaceId của bạn"
ROXY_PROJECT_ID = "projectId của bạn"
ROXY_ONE_PROFILE_PER_ACCOUNT = True
ROXY_DELETE_PROFILE_AFTER_RUN = True
ROXY_CREATE_USE_PROXY_POOL = True
```

Muốn headless:

```python
ROXY_OPEN_HEADLESS = True
```

#### Đăng ký bằng CloakBrowser

Đổi sang CloakBrowser thì cài dependency trước:

```bash
pip install -r requirements.txt
```

Rồi trong `config/roxybrowser.py` hoặc trang cấu hình WebUI đổi driver:

```python
REGISTRATION_DRIVER = "cloak"
```

Trong `config/codex.py` hoặc nhóm «CPA / Codex» trên WebUI, đặt driver uỷ quyền Codex:

```python
CODEX_OAUTH_DRIVER = "same_as_registration"  # theo driver đăng ký
# hoặc chỉ định: "protocol" / "roxy" / "cloak" / "browser_use"
```

Cấu hình riêng CloakBrowser ở `config/cloakbrowser.py`:

```python
CLOAK_HEADLESS = False          # True=headless; False=hiện cửa sổ
CLOAK_HUMANIZE = True           # chuột/bàn phím/cuộn kiểu người
CLOAK_GEOIP = True              # tự khớp ngôn ngữ/múi giờ/WebRTC theo IP đầu ra
CLOAK_LOCALE = ""               # để trống = tự động; hoặc ép ja-JP / en-US
CLOAK_TIMEZONE = ""             # để trống = tự động; hoặc ép Asia/Tokyo
CLOAK_LICENSE_KEY = ""          # để trống = binary miễn phí; Pro key = bản mới
CLOAK_FINGERPRINT_SEED = ""     # để trống = mỗi lần ngẫu nhiên; cố định = cùng fingerprint
CLOAK_USER_DATA_DIR = ""        # để trống = môi trường tạm; điền path để giữ profile
```

Ghi chú:

- `CLOAK_GEOIP=True` tự sinh `locale / timezone / Accept-Language` theo IP đầu ra hiện tại, rồi truyền cho CloakBrowser và Playwright context.
- Nếu dùng proxy qua kho proxy của project, điền `PROXY_POOL` trong `config/proxy.py`. Proxy hệ thống/VPN cũng được định vị theo IP đầu ra thực tế.
- Bản miễn phí không giới hạn số cửa sổ phía project. Mỗi tác vụ đăng ký khởi chạy một instance CloakBrowser, tức một fingerprint.
- Trên WebUI, `Codex授权驱动` nằm ở nhóm «CPA / Codex», tương ứng `CODEX_OAUTH_DRIVER` trong `config/codex.py`. Nhãn field WebUI có thể còn tiếng Trung cho đến khi bản dịch UI land.

#### Đăng ký giao thức

```python
REGISTRATION_DRIVER = "protocol"
```

Đăng ký giao thức dùng `curl_cffi`, Sentinel/PoW, kho proxy, v.v.

#### Đăng ký bằng Browser Use Cloud

```python
REGISTRATION_DRIVER = "browser_use"
```

Điền trong `config/browser_use.py` hoặc WebUI «Cấu hình → Browser Use»:

```python
BROWSER_USE_API_KEY = "Browser Use API Key của bạn"
BROWSER_USE_PROXY_COUNTRY_CODE = "jp"   # tuỳ chọn: us/sg/de...
BROWSER_USE_USE_PROXY = True
BROWSER_USE_FAST_MODE = True       # nên bật: giảm chờ thêm của Browser Use
BROWSER_USE_LOG_TIMING = True      # log thời gian từng pha, để tìm chỗ chậm
BROWSER_USE_SESSION_TIMEOUT = 240  # keepAlive/timeout Browser Use, đơn vị phút; giữ trình duyệt remote sống lâu hơn lúc tạo
```

Muốn sau đăng ký thành công cũng dùng Browser Use chạy Codex OAuth:

```python
ENABLE_CODEX_AUTO = True
CODEX_OAUTH_DRIVER = "browser_use"
# hoặc CODEX_OAUTH_DRIVER = "same_as_registration" khi REGISTRATION_DRIVER="browser_use"
```

Dependency:

```bash
uv pip install playwright --python .venv/bin/python
# hoặc
pip install playwright
```

Ghi chú research:

- Browser Use dùng stealth Chromium remote, điều khiển bằng Playwright `connect_over_cdp`.
- `BROWSER_USE_SESSION_TIMEOUT=240` đặt keepAlive dài khi Browser Use tạo/kết nối trình duyệt remote (tham số `timeout` trên connect URL, đơn vị phút), tránh phiên cloud bị thu hồi khi chờ OTP email, SMS hoặc callback. Code clamp về `1~240`.
- Lần đầu vào trang mã OTP email mà hộp thư đã có mã nhưng chương trình không lấy được: thường là đường lấy thư Outlook rung. Graph TLS/REST/IMAP fail một vòng, lát poll ngắn quá, hoặc biên `after_ts` quá chặt. Driver Browser Use đã nới lát lấy thư Outlook mỗi vòng, ghi sớm thời điểm lọc mã, và sau timeout chờ OTP email sẽ thử bấm gửi lại rồi chờ tiếp. Nút gửi lại định vị bằng heuristic cấu trúc/vị trí/thuộc tính DOM, không dựa copy trang hay OCR. Ở «Email / OTP» tăng `OTP_MAX_WAIT` lên `180~240`; `OUTLOOK_FETCH_MODE` ưu tiên `auto`.
- Log lấy thư Outlook hiện nguồn mã: `source=graph`, `source=outlook_rest`, `source=imap_new`, `source=imap_entra_outlook`, `source=remote_graph` hoặc `source=remote_imap`.
- `BROWSER_USE_FAST_MODE=True` bỏ hầu hết chờ nhịp người. `BROWSER_USE_LOG_TIMING=True` in thời gian các pha kết nối, mở trang, email, OTP, điện thoại, callback.
- Dùng được làm driver uỷ quyền Codex: `CODEX_OAUTH_DRIVER="browser_use"`, làm trang uỷ quyền, OTP email, xác minh SMS và bắt callback.
- Hợp khi không muốn cài Roxy local nhưng cần cô lập session + proxy cloud.
- Hạn mức miễn phí/đồng thời theo trang giá Browser Use.

---

### 3. Cấu hình proxy

Sửa `config/proxy.py`:

```python
PROXY_POOL = [
    "http://user:pass@host:port",
]
```

Khi Roxy một tài khoản một profile và `ROXY_CREATE_USE_PROXY_POOL=True`, proxy lấy ngẫu nhiên từ đây ghi vào Roxy Profile.

---

### 4. Cấu hình Codex OAuth

Không cần Codex thì tắt:

```python
ENABLE_CODEX_AUTO = False
```

Cần uỷ quyền tự động:

```python
ENABLE_CODEX_AUTO = True
# config/codex.py
CODEX_OAUTH_DRIVER = "browser_use"  # protocol / roxy / cloak / browser_use / skyvern / same_as_registration
```

Cấu hình nhận OTP SMS trong `config/codex.py`:

```python
SMS_PROVIDER = "l"        # grizzly / l / h
SMS_API_KEY = "GrizzlySMS key của bạn"  # chỉ GrizzlySMS cần
SMS_SERVICE = "openai"
SMS_COUNTRY = "mã quốc gia"
SMS_MAX_RETRIES = 10
SMS_CODE_WAIT = 120
SMS_POLL_INTERVAL = 5

# Nếu SMS_PROVIDER="h", H map cố định:
#   SMS_SERVICE -> H projectId
#   SMS_COUNTRY -> H country
H_API_BASE = "http://localhost:8788"
H_ADMIN_AUTH_CODE = "mã uỷ quyền admin H của bạn"
```

Nguồn URL uỷ quyền CPA:

```python
CODEX_AUTH_URL_SOURCE = "cpa"
CPA_MANAGEMENT_URL = "địa chỉ quản trị CPA của bạn"
CPA_MANAGEMENT_KEY = "khoá quản trị CPA của bạn"
```

---

## Cách dùng

## WebUI (khuyến nghị)

Nên quản lý nền bằng một script ở gốc project:

```bash
./webui.sh start      # khởi chạy
./webui.sh stop       # dừng
./webui.sh restart    # restart
./webui.sh status     # trạng thái
./webui.sh logs       # xem log realtime
```

Script mặc định `http://127.0.0.1:5000`, log vào `logs/webui.log`, PID vào `run/webui.pid`.

Chỉnh bằng biến môi trường:

```bash
PORT=8000 OPEN_BROWSER=1 ./webui.sh start
HOST=0.0.0.0 PORT=5000 ./webui.sh restart
AUTH_CODE=mã-uỷ-quyền-của-bạn ./webui.sh start
```

Cũng chạy foreground:

```bash
python web.py --open-browser
```

Địa chỉ mặc định:

```text
http://127.0.0.1:5000
```

Chỉ định cổng:

```bash
python web.py --port 8000 --open-browser
```

Cho LAN truy cập:

```bash
python web.py --host 0.0.0.0 --port 5000
```

Trang WebUI:

| Trang | Chức năng |
|---|---|
| Đăng ký | Đặt số lượng, số luồng, khởi chạy đăng ký hàng loạt, xem tác vụ và nhật ký |
| Tài khoản | Xem tài khoản, sao chép token, bổ chạy Codex, xoá tài khoản hàng loạt |
| Uỷ quyền Codex | Xem/tải/xoá credential Codex trong SQLite |
| Kho email | Nhập email, lọc nguồn, đánh dấu khả dụng/thất bại, xoá email |
| Cấu hình | Sửa cấu hình runtime và hot-reload: Roxy, Codex, email, proxy, nhịp người |

### Số luồng

- Số luồng đăng ký đọc mỗi lần bấm «Bắt đầu đăng ký».
- Nếu số luồng khác lần trước, tác vụ mới dùng pool luồng mới.
- Tác vụ đã xếp hàng/đang chạy trong pool cũ chạy nốt, không bị huỷ cưỡng bức.
- Bổ chạy Codex hàng loạt mỗi lần tạo pool luồng riêng theo số luồng của lần gửi đó.

---

## CLI

Đăng ký 1 tài khoản:

```bash
python main.py
```

Đăng ký 10, 3 luồng:

```bash
python main.py -n 10 --workers 3 --continue-on-fail
```

Log chi tiết:

```bash
python main.py -n 1 --verbose
```

Tham số:

| Tham số | Mô tả | Mặc định |
|---|---|---|
| `-n, --count` | Số lượng đăng ký | 1 |
| `--workers` | Số luồng đồng thời | 1 |
| `--delay` | Giây nghỉ sau mỗi lần đăng ký | 0 |
| `--continue-on-fail` | Thất bại một tài khoản vẫn tiếp tục | False |
| `--verbose` | Log DEBUG | False |

---

## Bổ chạy Codex

Trang tài khoản WebUI bổ chạy Codex đơn hoặc hàng loạt.

CLI bổ chạy riêng:

```bash
python tools/test_codex_oauth.py --email <email-đã-đăng-ký> --verbose
```

Bổ chạy tiêu tốn:

- 1 OTP email
- 1 số nhận OTP SMS

Log bổ chạy nằm ở đường dẫn runtime (đừng đổi tên thư mục):

```text
注册日志/codex-retry-邮箱.log
```

`注册日志/` là thư mục log hardcoded. `邮箱` trong tên file là placeholder email.

---

## Mật khẩu đăng ký

Nếu đăng ký Roxy gặp luồng mới:

```text
/create-account/password
```

sẽ tự đặt mật khẩu.

Nguồn mật khẩu:

1. Ưu tiên `config/register.py`:

```python
REGISTER_PASSWORD = "mật-khẩu-cố-định-của-bạn"
```

2. Nếu trống, tự sinh mật khẩu mạnh 14 ký tự, gồm hoa, thường, số, ký hiệu.

Nơi lưu:

- `extra_json.registration_password` của tài khoản
- `extra_json.registration_password` trong `accounts.payload` của SQLite

Lưu ý: field `password` trên bảng tài khoản vẫn là mật khẩu vật liệu email Outlook, không bị mật khẩu đăng ký OpenAI ghi đè.

---

## File cấu hình quan trọng

| File | Mô tả |
|---|---|
| `config/roxybrowser.py` | Driver đăng ký, Roxy API, vòng đời môi trường Roxy |
| `config/cloakbrowser.py` | CloakBrowser: headless/humanize/geoip/ngôn ngữ-múi giờ/fingerprint seed |
| `config/codex.py` | Codex OAuth, driver uỷ quyền, CPA management API, nền tảng nhận OTP SMS |
| `config/email.py` | Nguồn email, poll OTP, QQ IMAP, email domain, email tạm Cloudflare Worker |
| `config/proxy.py` | Kho proxy |
| `config/register.py` | Email, mật khẩu, tên hiển thị mặc định |
| `config/twofa.py` | Công tắc 2FA |
| `config/humanize.py` | Tạm dừng ngẫu nhiên / nhịp người |
| `config/flow_trigger.py` | Gọi Flow sau đăng ký thành công |
| `config/browser.py` | Fingerprint trình duyệt chế độ giao thức |
| `config/openai_protocol.py` | Tham số OpenAI OAuth/Sentinel |

Sau khi lưu trang cấu hình WebUI sẽ hot-reload. Roxy, Codex, email, proxy, nhịp người và các mục thường dùng có hiệu lực ngay.

---

## Dữ liệu và sản phẩm

| Đường dẫn | Nội dung |
|---|---|
| `turb.sqlite3` | Toàn bộ tài khoản, kho email, tác vụ, credential Codex và Agent |
| JSON/TXT/Codex cũ | Chỉ để migrate lần đầu; runtime không đọc/ghi nữa |
| `注册日志/` | Nhật ký tác vụ đăng ký, nhật ký bổ chạy Codex |

---

## Luồng chính hiện tại

### Luồng đăng ký Roxy

```text
Tạo/mở Roxy Profile
  ↓
Mở chatgpt.com/auth/login
  ↓
Định vị ô email theo thuộc tính kỹ thuật DOM, tránh bấm nhầm Google/Apple/Microsoft
  ↓
Gửi form email
  ↓
Nếu vào create-account/password: đặt mật khẩu và gửi
  ↓
Chờ trang mã OTP email
  ↓
Đọc OTP email và gửi
  ↓
Nếu vào about-you/profile: điền tên + tuổi hoặc ngày sinh
  ↓
Vào ChatGPT, đọc accessToken từ /api/auth/session
  ↓
2FA tuỳ chọn
  ↓
Codex OAuth tuỳ chọn
  ↓
Lưu tài khoản vào SQLite
  ↓
Đóng/xoá Roxy Profile
```

### Luồng uỷ quyền Codex trên Roxy

```text
Lấy URL uỷ quyền Codex (CPA hoặc local PKCE)
  ↓
Roxy mở trang uỷ quyền
  ↓
Đăng nhập email + OTP email
  ↓
Xác minh số điện thoại: lấy số → điền số → gửi → chờ SMS → điền OTP
  ↓
Chờ consent/workspace/callback
  ↓
Nộp callback cho CPA hoặc đổi token local
  ↓
Lưu credential Codex vào SQLite
```

---

## Câu hỏi thường gặp

### Lưu cấu hình mà không có hiệu lực?

Trang cấu hình WebUI hot-reload sau khi lưu. Trước khi luồng bổ chạy Codex khởi động cũng hot-reload cấu hình một lần nữa.

Nếu sửa tay `config/*.py`, tiến trình CLI cần restart. WebUI nên sửa trên trang cấu hình.

### Đã lưu Roxy headless mà vẫn hiện cửa sổ?

Kiểm tra:

```python
ROXY_OPEN_HEADLESS = True
```

Và xác nhận bản Roxy hỗ trợ tham số `headless` của `/browser/open`. Log in giá trị `headless` thực sự truyền đi.

### IP đầu ra không phải Nhật thì bấm vào đăng nhập Google?

Cổng email đăng ký Roxy hiện chỉ định vị theo thuộc tính kỹ thuật DOM, và loại nút đăng nhập bên thứ ba. Không còn khớp chữ nút “Continue”.

### Codex hiện `Check your phone` bị coi là thất bại nhầm?

Đã tương thích: `Check your phone / Enter the verification code...` được nhận là trang mã OTP điện thoại, rồi vào luồng chờ SMS.

### Gửi OTP điện thoại xong log từng hiện thất bại, nhưng sau đó thành công?

Đã sửa: sau khi gửi OTP điện thoại sẽ chờ trang rời luồng số điện thoại hoặc tới callback, không còn dùng copy trang cũ sau 3 giây để kết luận thất bại.

### Codex thất bại nhưng đăng ký thành công thì sao?

Tài khoản vẫn được lưu, trạng thái Codex đánh thất bại. Bổ chạy trên trang tài khoản WebUI, hoặc:

```bash
python tools/test_codex_oauth.py --email <email> --verbose
```

### Cấu hình email Cloudflare Worker thế nào?

Đặt `EMAIL_SOURCE` = `cloudflare`, và cấu hình `CLOUDFLARE_API_BASE` cùng các field liên quan (xem «Email tạm Cloudflare Worker» ở trên).
Khác nguồn `cloudflare_domain` (forward QQ IMAP).

### Không có nền tảng nhận OTP SMS thì đăng ký được không?

Được. Tắt:

```python
ENABLE_CODEX_AUTO = False
```

Luồng đăng ký chính không phụ thuộc nhận OTP SMS. Chỉ uỷ quyền Codex tự động mới cần.

---

## Cấu trúc project

```text
.
├── main.py                         # cổng CLI
├── web.py                          # cổng WebUI
├── config/                         # cấu hình
│   ├── roxybrowser.py              # driver đăng ký/Codex RoxyBrowser
│   ├── cloakbrowser.py             # cấu hình driver đăng ký CloakBrowser
│   ├── browser_use.py              # cấu hình Browser Use Cloud
│   ├── codex.py                    # Codex OAuth / driver uỷ quyền / CPA / nhận OTP SMS
│   ├── email.py                    # nguồn email/OTP
│   ├── proxy.py                    # kho proxy
│   ├── register.py                 # thông tin đăng ký mặc định
│   └── ...
├── core/
│   ├── browser_data_saver.py       # chặn tài nguyên tiết kiệm data Roxy/Cloak local
│   ├── browser_traffic.py          # thống kê lưu lượng HTTP/WebSocket lúc đăng ký
│   ├── roxy_registration.py        # luồng trang đăng ký Roxy / trình duyệt
│   ├── cloakbrowser_registration.py # cổng đăng ký Cloak
│   ├── cloakbrowser_driver.py      # lớp thích ứng Cloak Playwright→kiểu Selenium
│   ├── browser_use_registration.py # luồng đăng ký Browser Use + Playwright
│   ├── browser_use_client.py       # client CDP Browser Use
│   ├── roxy_codex_oauth.py         # luồng trang Codex OAuth trên Roxy / Cloak
│   ├── roxybrowser_client.py       # client Roxy API
│   ├── registration_service.py     # pool luồng đăng ký WebUI
│   ├── codex_oauth.py              # điều phối Codex giao thức/Roxy/Cloak
│   ├── email_provider.py           # điều phối nguồn email
│   ├── cf_temp_mail_client.py      # email tạm Cloudflare Worker
│   ├── sms_provider.py             # nền tảng nhận OTP SMS
│   ├── account_export.py           # xử lý sau đăng ký và lưu SQLite
│   └── db.py                       # SQLite và migrate một lần
├── webui/
│   ├── app.py                      # Flask API
│   ├── config_editor.py            # đọc/ghi cấu hình / hot-reload
│   └── templates/index.html        # console một trang
├── sentinel/
│   ├── sdk.js
│   └── sentinel-runner.js
├── tools/
│   └── test_codex_oauth.py         # bổ chạy Codex riêng
└── L_API.md                        # mô tả API nhận OTP L local
```

---

## Gợi ý khi research

- Research hàng loạt nên dùng WebUI; đừng mở nhiều tiến trình CLI cùng lúc.
- Số luồng đăng ký không nên vượt số proxy dùng được.
- Roxy một tài khoản một profile nên giữ bật, giảm nhiễm môi trường.
- Khi debug trang, tạm đặt:

```python
ROXY_KEEP_BROWSER_OPEN = True
ROXY_OPEN_HEADLESS = False
```

- Debug xong thì trả về tự đóng/xoá môi trường.

---

## Cảm ơn

- [LINUX DO](https://linux.do) — trao đổi cộng đồng và phản hồi người dùng
- [RoxyBrowser](https://roxybrowser.cn/invite/NvH4Jx) — tặng 5 cửa sổ
- [CloakBrowser](https://github.com/CloakHQ/CloakBrowser) — hỗ trợ trình duyệt fingerprint tự động hoá Stealth Chromium / Playwright
- [browser-use](https://github.com/browser-use/browser-use) — năng lực trình duyệt cloud Browser Use Cloud / Playwright CDP
- [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) — tham chiếu định dạng credential Codex OAuth
- [curl_cffi](https://github.com/yifeikong/curl_cffi) — thư viện HTTP nền, impersonate fingerprint TLS

---

## License

MIT

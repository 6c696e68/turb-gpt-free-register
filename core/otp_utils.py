# -*- coding: utf-8 -*-
"\nOTP phát hiện và công cụ trích dùng công cụ, bị outlook_client(Outlook email)dùng. \n\nyêu cầu: \n  - nhận diện từ khoá đa ngôn ngữ(Anh / trong / Nhật / Hàn)\n  - trường tên dung sai(khác thư API dùng khác trường lệnh tên quy ước)\n  - trên dưới văn ưu tiên: ở nhiều 6 chữ số số trong, chọn gần\"mã OTP\"v.v.từ khoá gần nhất đó \n"
import re

_OPENAI_SENDER_HINT = "openai"

# 多语言关键字（用于判断是否是 OpenAI 邮件）
_OPENAI_KEYWORDS = (
    "chatgpt", "openai",
    # 英文
    "verification code", "code is", "your code", "verify your email",
    # 中文
    "代码", "验证码", "确认码",
    # 日文
    "認証コード", "検証コード", "確認コード", "一時検証", "認証",
    # 韩文
    "인증 코드", "확인 코드",
)

# OTP 上下文关键字（用于在多个 6 位数中挑出真正的验证码）
_OTP_CONTEXT_KEYWORDS = (
    "code", "verify", "verification",
    "代码", "验证", "确认",
    "コード", "認証", "検証", "確認",
    "코드", "인증",
)

_OTP_REGEX = re.compile(r"\b(\d{6})\b")


def _get_field(item: dict, *names: str) -> str:
    "\n  từ thư dict trong theo thử theo thứ tự nhiều có thể có thể trường tên, trả về lần một không trống chuỗi. \n  dùng để tương thích khác thư API  trường lệnh tên quy ước(ví dụ như sendEmail / from / fromEmail / from.address). \n  "
    for name in names:
        if "." in name:
            # 支持 "from.emailAddress.address" 这种点路径
            value = item
            for part in name.split("."):
                if not isinstance(value, dict):
                    value = None
                    break
                value = value.get(part)
            if isinstance(value, str) and value:
                return value
        else:
            value = item.get(name)
            if isinstance(value, str) and value:
                return value
    return ""


def looks_like_openai_email(item: dict) -> bool:
    "\n  xác định thư là có phải từ OpenAI / ChatGPT. đa ngôn ngữ, nhiều trường tên tương thích. \n\n  trường tên dung sai(khác API trả về phong cách không một): \n  người gửi:  sendEmail / from / fromEmail / from.emailAddress.address\n  người gửi tên:sendName / fromName / from.emailAddress.name\n  văn bản thuần này:  text / bodyPreview / bodyText\n  HTML:  content / body / html / body.content / bodyHtml\n  "
    sender = _get_field(item, "sendEmail", "from", "fromEmail", "from.emailAddress.address").lower()
    sender_name = _get_field(item, "sendName", "fromName", "from.emailAddress.name").lower()
    subject = _get_field(item, "subject").lower()
    text = _get_field(item, "text", "bodyPreview", "bodyText").lower()
    content = _get_field(item, "content", "body", "html", "body.content", "bodyHtml").lower()

    if _OPENAI_SENDER_HINT in sender or _OPENAI_SENDER_HINT in sender_name:
        return True

    return any(k in s for s in (subject, text, content) for k in _OPENAI_KEYWORDS)


def extract_otp(item: dict) -> str | None:
    "\n  từ thư trong trích ra 6 chữ số OTP. \n\n  thứ tự trích: \n  1. subject(OpenAI một phần thư trực tiếp  6 chữ số số đặt ở chính trong tiêu đề, ví dụ \"Your OpenAI code is 525210\")\n  2. văn bản thuần này trường(text / bodyPreview / bodyText)\n  3. HTML trường(content / html / body / body.content / bodyHtml, bỏ thẻ sau)\n\n  nếu body trong chứa nhiều 6 chữ số số, ưu tiên chọn gần \"mã OTP / code / xác thực\" v.v.từ khoá gần nhất đó . \n  "
    # 1. 主题里如果直接有 6 位数，最可信
    subject = _get_field(item, "subject")
    if subject:
        codes_in_subject = _OTP_REGEX.findall(subject)
        if len(codes_in_subject) == 1:
            # 主题里恰好只有一个 6 位数，几乎肯定就是 OTP
            return codes_in_subject[0]

    # 2. body 字段
    candidates = [
        ("text", _get_field(item, "text", "bodyPreview", "bodyText")),
        ("html", _get_field(item, "content", "html", "body", "body.content", "bodyHtml")),
    ]

    for kind, body in candidates:
        if not body:
            continue
        # 无论 text 还是 html，都先去 HTML 标签和 style 属性
        # （QQ 邮箱转发的 OpenAI 邮件，text 字段也可能含 HTML）
        body = re.sub(r"<style[^>]*>.*?</style>", " ", body, flags=re.DOTALL | re.IGNORECASE)
        body = re.sub(r"<[^>]+>", " ", body)
        all_codes = _OTP_REGEX.findall(body)
        if not all_codes:
            continue
        body_lower = body.lower()
        # 优先选离上下文关键字最近的 6 位数
        for code in all_codes:
            idx = body_lower.find(code)
            if idx < 0:
                continue
            window = body_lower[max(0, idx - 60): idx + 6 + 60]
            if any(k.lower() in window for k in _OTP_CONTEXT_KEYWORDS):
                return code
        return all_codes[0]
    return None

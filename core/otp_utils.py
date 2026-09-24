# -*- coding: utf-8 -*-
"""
OTP detect và rút lấy thông dùng công công cụ ， bị outlook_client（Outlook email）dùng。

cần yêu cầu ：
- nhiều ngôn lời liên quan khoá ký tự nhận diện（Anh / / ngày / Hàn ）
- trườngtên dung sai （không cùng thư mục API dùng không cùng trườngmệnh tên ước định ）
- ngữ cảnhưu trước ：tại nhiều 6 sốsố ，chọn chọn rời \"mã OTP\" v.v.liên quan khoá ký tự nhất gần đó
"""
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
    """
từthư mục dict theo thuận thứ tự thử thử nhiều có thể có thể trườngtên ，trả vềlần một không trống ký tự ký hiệu chuỗi 。
dùng chokiêm dung không cùng thư mục API trườngmệnh tên ước định （ví dụ nếu sendEmail / from / fromEmail / from.address）。
"""
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
    """
phán ngắt thư mục là không đến tự OpenAI / ChatGPT。nhiều ngôn lời 、nhiều trườngtên kiêm dung 。

trườngtên dung sai （không cùng API trả vềgió ô không một ）：
gửi mục người : sendEmail / from / fromEmail / from.emailAddress.address
gửi mục người tên :sendName / fromName / from.emailAddress.name
thuần văn này : text / bodyPreview / bodyText
HTML: content / body / html / body.content / bodyHtml
"""
    sender = _get_field(item, "sendEmail", "from", "fromEmail", "from.emailAddress.address").lower()
    sender_name = _get_field(item, "sendName", "fromName", "from.emailAddress.name").lower()
    subject = _get_field(item, "subject").lower()
    text = _get_field(item, "text", "bodyPreview", "bodyText").lower()
    content = _get_field(item, "content", "body", "html", "body.content", "bodyHtml").lower()

    if _OPENAI_SENDER_HINT in sender or _OPENAI_SENDER_HINT in sender_name:
        return True

    return any(k in s for s in (subject, text, content) for k in _OPENAI_KEYWORDS)


def extract_otp(item: dict) -> str | None:
    """
từthư mục rút ra 6 số OTP。

rút lấy thuận thứ tự ：
1. subject（OpenAI bộ phần thư mục trực tiếp 6 sốsố đặt tại chính đề trong ，ví dụ \"Your OpenAI code is 525210\"）
2. thuần văn này trường（text / bodyPreview / bodyText）
3. HTML trường（content / html / body / body.content / bodyHtml，đi nhãn ký sau）

nếu body gồm nhiều 6 sốsố ，ưu trước chọn chọn rời \"mã OTP / code / nhận chứng \" v.v.liên quan khoá ký tự nhất gần đó 。
"""
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

# -*- coding: utf-8 -*-
"""Nạp khoá/cấu hình nhạy cảm từ .env ở gốc project.

Mục tiêu:
  - API Key quan trọng không nằm trong mặc định config/*.py được git theo dõi
  - module config đọc biến môi trường lúc khởi động / reload
  - WebUI đọc/ghi field khoá trong .env
"""
from __future__ import annotations

import os
import re
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_PATH = _PROJECT_ROOT / ".env"
_LOADED = False

# Các field list nhiều dòng này cho phép giá trị trống ghi đè tường minh thành [].
# Ví dụ WebUI xoá sạch kho proxy sẽ ghi PROXY_POOL="" / PROXY_POOL="[]", không được fallback về proxy local mặc định trong source.
EXPLICIT_EMPTY_LIST_ENV_KEYS = {"PROXY_POOL", "PLAN_CHECK_PROXY"}

# Quản lý tập trung: env key -> mô tả (dùng cho .env.example)
SECRET_ENV_KEYS: dict[str, str] = {
    "WEBUI_AUTH_CODE": "Mã uỷ quyền đăng nhập WebUI",
    "WEBUI_SESSION_SECRET": "Khoá ký Session Cookie WebUI",
    "BROWSER_USE_API_KEY": "Browser Use Cloud API Key",
    "SKYVERN_API_KEY": "Skyvern API Key",
    "ROXY_API_TOKEN": "Token API local RoxyBrowser",
    "PLAN_CHECK_PROXY": "Proxy riêng tra gói (có thể chứa thông tin xác thực)",
    "PLAN_CHECK_UPSTREAM_PROXY": "Địa chỉ proxy upstream local cho tra gói (chuỗi proxy)",
    "PROXY_POOL_UPSTREAM_PROXY": "Địa chỉ proxy upstream local của kho proxy (chuỗi proxy)",
    "QQ_IMAP_PASSWORD": "Mã uỷ quyền IMAP email QQ (không phải mật khẩu QQ)",
    "GPTMAIL_API_KEY": "GPTMail API Key",
    "CLOUDFLARE_API_KEY": "API Key / ADMIN_PASSWORD email tạm Cloudflare Worker",
    "CLOUDFLARE_CUSTOM_AUTH": "Mật khẩu toàn cục Cloudflare Worker x-custom-auth",
    "MAIL_NEST_API_KEY": "MailNest API Key",
    "CLOUDMAIL_AUTH_TOKEN": "CloudMail Authorization Token",
    "CLOUDMAIL_PASSWORD": "Mật khẩu đăng nhập CloudMail",
    "REMAIL_API_KEY": "Remail Open API Key",
    "CPA_MANAGEMENT_KEY": "Khoá CPA management API",
    "EXTRACT_LINK_CDK": "CDK dịch vụ rút link",
    "SUB2API_API_KEY": "API Key management sub2api",
    "SUB2API_API_TOKEN": "Token xác thực management sub2api (tên cấu hình cũ, tương thích)",
    "SMS_API_KEY": "API Key nền tảng nhận OTP SMS (ví dụ GrizzlySMS)",
    "SMSBOWER_API_KEY": "SMSBower API Key",
    "L_ADMIN_AUTH_CODE": "ADMIN_AUTH_CODE dịch vụ nhận OTP L local",
    "H_ADMIN_AUTH_CODE": "ADMIN_AUTH_CODE dịch vụ nhận OTP H local",
}


def env_path() -> Path:
    return _ENV_PATH


def load_env(*, override: bool = False) -> Path:
    """Nạp .env gốc project vào môi trường tiến trình. Gọi lại được (reload dùng override=True).

    Ưu tiên python-dotenv; chưa cài thì dùng parser nhẹ trong file này, tránh phụ thuộc cứng khi đọc cấu hình.
    """
    global _LOADED
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover
        if _ENV_PATH.exists():
            for key, value in read_env_file().items():
                if override or key not in os.environ:
                    os.environ[key] = value
        _LOADED = True
        return _ENV_PATH

    if _ENV_PATH.exists():
        load_dotenv(dotenv_path=_ENV_PATH, override=override)
    else:
        # Vẫn cho biến môi trường hệ thống có hiệu lực
        load_dotenv(override=override)
    _LOADED = True
    return _ENV_PATH


def ensure_loaded() -> None:
    if not _LOADED:
        load_env(override=False)


def env_str(key: str, default: str = "") -> str:
    ensure_loaded()
    value = os.getenv(key)
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip()


def _escape_env_value(value: str) -> str:
    # Thống nhất dấu nháy kép, tránh lỗi khoảng trắng/ký tự đặc biệt
    escaped = (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "")
    )
    return f'"{escaped}"'


def read_env_file() -> dict[str, str]:
    """Parse file .env thành dict (không phụ thuộc os.environ)."""
    if not _ENV_PATH.exists():
        return {}
    out: dict[str, str] = {}
    for raw in _ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if not key:
            continue
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
            val = val.replace("\\n", "\n").replace("\\\"", '"').replace("\\\\", "\\")
        out[key] = val
    return out


def write_env_values(updates: dict[str, str]) -> list[str]:
    """Cập nhật một số key trong .env; chưa có thì nối thêm. Trả danh sách key thực sự ghi."""
    if not updates:
        return []

    existing_lines: list[str] = []
    if _ENV_PATH.exists():
        existing_lines = _ENV_PATH.read_text(encoding="utf-8").splitlines()

    remaining = {str(k): ("" if v is None else str(v)) for k, v in updates.items()}
    written: list[str] = []
    out_lines: list[str] = []
    key_re = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")

    for line in existing_lines:
        m = key_re.match(line)
        if not m:
            out_lines.append(line)
            continue
        key = m.group(1)
        if key in remaining:
            out_lines.append(f"{key}={_escape_env_value(remaining.pop(key))}")
            written.append(key)
        else:
            out_lines.append(line)

    if remaining:
        if out_lines and out_lines[-1].strip():
            out_lines.append("")
        out_lines.append("# ---- updated by WebUI / config.env_loader ----")
        for key, value in remaining.items():
            out_lines.append(f"{key}={_escape_env_value(value)}")
            written.append(key)

    text = "\n".join(out_lines).rstrip() + "\n"
    tmp = _ENV_PATH.with_suffix(".env.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(_ENV_PATH)

    # Để tiến trình hiện tại thấy giá trị mới ngay
    load_env(override=True)
    return written


def _coerce_env_value(raw: str, default, vtype: str | None = None):
    if vtype is None:
        if isinstance(default, bool):
            vtype = "bool"
        elif isinstance(default, int) and not isinstance(default, bool):
            vtype = "int"
        elif isinstance(default, float):
            vtype = "float"
        elif isinstance(default, (list, tuple)):
            vtype = "list_str_multiline"
        else:
            vtype = "str"
    if vtype == "bool":
        return str(raw).strip().lower() in ("true", "1", "yes", "on", "y")
    if vtype == "int":
        return int(str(raw).strip())
    if vtype == "float":
        return float(str(raw).strip())
    if vtype == "list_str_multiline":
        text = str(raw)
        # Tương thích giá trị cũ: PROXY_POOL='["http://..."]'
        try:
            import ast
            val = ast.literal_eval(text)
            if isinstance(val, (list, tuple)):
                return [str(x).strip() for x in val if str(x).strip()]
        except Exception:
            pass
        return [line.strip() for line in text.splitlines() if line.strip()]
    return str(raw).strip()


def env_value(key: str, default=None, vtype: str | None = None):
    ensure_loaded()
    raw = os.getenv(key)
    # `.env.example` và WebUI hay có cấu hình trống `KEY=` / `KEY=""`.
    # Giá trị trống nghĩa là "chưa cấu hình, dùng mặc định trong config/*.py"; nếu không, bool mặc định True
    # sẽ bị chuỗi rỗng ghi đè thành False, mặc định str/list cũng bị xoá nhầm.
    if raw is None:
        return default
    if str(raw).strip() == "":
        if vtype == "list_str_multiline" and key in EXPLICIT_EMPTY_LIST_ENV_KEYS:
            return []
        return default
    try:
        return _coerce_env_value(raw, default, vtype)
    except Exception:
        return default


def env_bool(key: str, default: bool = False) -> bool:
    return bool(env_value(key, default, "bool"))


def env_int(key: str, default: int = 0) -> int:
    return int(env_value(key, default, "int"))


def env_float(key: str, default: float = 0.0) -> float:
    return float(env_value(key, default, "float"))


def env_list(key: str, default: list[str] | None = None) -> list[str]:
    return list(env_value(key, default or [], "list_str_multiline"))


def apply_env_overrides(namespace: dict, schema: dict[str, str] | None = None) -> None:
    """Ghi đè hằng số cấu hình trong globals() của module bằng .env/biến môi trường.

    schema: {KEY: type}, type hỗ trợ bool/int/float/str/list_str_multiline.
    Không truyền schema thì suy type theo giá trị mặc định của hằng số viết hoa đã có trong namespace.
    """
    ensure_loaded()
    keys = schema.keys() if schema else [k for k in namespace if k.isupper()]
    for key in keys:
        if os.getenv(key) is None:
            continue
        default = namespace.get(key)
        vtype = schema.get(key) if schema else None
        namespace[key] = env_value(key, default, vtype)

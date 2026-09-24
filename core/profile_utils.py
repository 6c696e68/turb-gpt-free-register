# -*- coding: utf-8 -*-
"""注册资料生成工具。"""

from __future__ import annotations

import random
from datetime import date, timedelta


def _shift_year_safe(day: date, years: int) -> date:
    """Dịch ngày theo năm; nếu gặp 29 tháng 2 và năm đích không phải năm nhuận thì lùi về 28 tháng 2."""
    try:
        return day.replace(year=day.year + years)
    except ValueError:
        return day.replace(year=day.year + years, month=2, day=28)


def generate_random_birthday(min_age: int = 18, max_age: int = 65) -> str:
    """
    Tạo ngày sinh ngẫu nhiên với tuổi trong đoạn đóng [min_age, max_age], định dạng YYYY-MM-DD.

    Ví dụ mặc định sẽ chọn ngẫu nhiên một ngày giữa “hôm nay đủ 65 tuổi” và “hôm nay đủ 18 tuổi”.
    """
    if min_age < 0 or max_age < min_age:
        raise ValueError(f"Khoảng tuổi không hợp lệ: min_age={min_age}, max_age={max_age}")

    today = date.today()
    oldest = _shift_year_safe(today, -max_age)
    youngest = _shift_year_safe(today, -min_age)
    span_days = (youngest - oldest).days
    birthday = oldest + timedelta(days=random.randint(0, span_days))
    return birthday.isoformat()

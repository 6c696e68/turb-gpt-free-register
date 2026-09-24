# -*- coding: utf-8 -*-
"""đăng kýtài liệu tạocông công cụ 。"""

from __future__ import annotations

import random
from datetime import date, timedelta


def _shift_year_safe(day: date, years: int) -> date:
    """theo năm lệch dịch ngày kỳ ；gặp đến 2 tháng 29 ngày và đíchnăm không nhuận năm khivề lùi đến 2 tháng 28 ngày 。"""
    try:
        return day.replace(year=day.year + years)
    except ValueError:
        return day.replace(year=day.year + years, month=2, day=28)


def generate_random_birthday(min_age: int = 18, max_age: int = 65) -> str:
    """
tạonăm tuổi tại [min_age, max_age] đóng vùng khoảng trong ngẫu nhiênsinh ngày ，định dạng YYYY-MM-DD。

ví dụ nếu mặc địnhsẽ ở“nay ngày đầy 65 tuổi ”đến “nay ngày đầy 18 tuổi ”của khoảng ngẫu nhiênlấy một ngày 。
"""
    if min_age < 0 or max_age < min_age:
        raise ValueError(f"Khoảng tuổi không hợp lệ: min_age={min_age}, max_age={max_age}")

    today = date.today()
    oldest = _shift_year_safe(today, -max_age)
    youngest = _shift_year_safe(today, -min_age)
    span_days = (youngest - oldest).days
    birthday = oldest + timedelta(days=random.randint(0, span_days))
    return birthday.isoformat()

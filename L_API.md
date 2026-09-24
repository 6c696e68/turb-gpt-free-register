# Tài liệu API lấy số L

Chỉ gồm các API phía tích hợp cần: lấy số, lấy mã OTP, giải phóng số. `service` và `country` do phía tích hợp tự cấu hình.

Chuỗi `error` / `message` trong JSON mẫu là phản hồi gốc của dịch vụ (tiếng Trung). Bảng bên dưới gloss tiếng Việt để đối chiếu log research; đừng đổi payload khi gọi API.

## Thông tin cơ bản

- Địa chỉ gốc API: `http://localhost:8788`
- Định dạng request/response: `application/json`
- API admin cần uỷ quyền:

```http
Authorization: Bearer <ADMIN_AUTH_CODE>
Content-Type: application/json
```

## 1. Lấy số

```http
POST /api/admin/l/take-phone
```

Tham số request:

```json
{
  "service": "facebook",
  "country": "10",
  "maxPrice": "0.05"
}
```

Giải thích field:

| Field | Bắt buộc | Mô tả |
| --- | --- | --- |
| `service` | Có | Mã dự án, phía tích hợp tự cấu hình |
| `country` | Có | ID quốc gia, phía tích hợp tự cấu hình |
| `maxPrice` | Không | Giá cao nhất chấp nhận |

Ví dụ request:

```sh
curl -s "http://localhost:8788/api/admin/l/take-phone" \
  -H "Authorization: Bearer <ADMIN_AUTH_CODE>" \
  -H "Content-Type: application/json" \
  -d '{"service":"facebook","country":"10","maxPrice":"0.05"}'
```

Phản hồi thành công:

```json
{
  "item": {
    "id": "f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35",
    "activationId": "67908f935ab3410bd4c7f757",
    "service": "facebook",
    "country": "10",
    "countryName": "",
    "price": "",
    "phone": "9091234661",
    "status": "active",
    "lastCode": "",
    "createdAt": "2026-06-29T03:30:00.000Z"
  },
  "raw": "ACCESS_NUMBER:67908f935ab3410bd4c7f757:9091234661"
}
```

Phía tích hợp cần lưu:

| Field | Mục đích |
| --- | --- |
| `item.id` | Dùng khi gọi API admin lấy mã OTP |
| `item.phone` | Số điện thoại đã lấy |

Lỗi thường gặp (payload gốc):

```json
{"error":"请选择服务"}
{"error":"请选择国家"}
{"error":"取号失败：暂无号码","raw":"NO_NUMBERS"}
{"error":"取号失败：余额不足","raw":"NO_BALANCE"}
```

| `error` gốc | Nghĩa |
| --- | --- |
| `请选择服务` | Vui lòng chọn dịch vụ |
| `请选择国家` | Vui lòng chọn quốc gia |
| `取号失败：暂无号码` | Lấy số thất bại: tạm hết số (`NO_NUMBERS`) |
| `取号失败：余额不足` | Lấy số thất bại: hết số dư (`NO_BALANCE`) |

## 2. Lấy mã OTP

```http
POST /api/admin/l/fetch-code
```

Tham số request:

```json
{
  "id": "f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35"
}
```

Ví dụ request:

```sh
curl -s "http://localhost:8788/api/admin/l/fetch-code" \
  -H "Authorization: Bearer <ADMIN_AUTH_CODE>" \
  -H "Content-Type: application/json" \
  -d '{"id":"f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35"}'
```

Phản hồi thành công:

```json
{
  "item": {
    "id": "f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35",
    "phone": "9091234661",
    "status": "code_received",
    "lastCode": "899201"
  },
  "code": "899201",
  "message": "L 验证码获取成功",
  "raw": "STATUS_OK:899201",
  "fetchedAt": "2026-06-29T03:32:00.000Z"
}
```

`message` gốc `L 验证码获取成功` = lấy mã OTP L thành công.

Chưa nhận được mã OTP:

```json
{
  "item": {
    "id": "f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35",
    "phone": "9091234661",
    "status": "active"
  },
  "code": "",
  "message": "等待验证码",
  "raw": "STATUS_WAIT_CODE",
  "fetchedAt": "2026-06-29T03:32:00.000Z"
}
```

`message` gốc `等待验证码` = đang chờ mã OTP (`STATUS_WAIT_CODE`).

Lỗi thường gặp (payload gốc):

```json
{"error":"缺少号码 ID"}
{"error":"号码不存在"}
{"error":"号码已释放，不能取验证码"}
```

| `error` gốc | Nghĩa |
| --- | --- |
| `缺少号码 ID` | Thiếu ID số |
| `号码不存在` | Số không tồn tại |
| `号码已释放，不能取验证码` | Số đã giải phóng, không lấy được mã OTP |

## 3. Giải phóng số

```http
POST /api/admin/l/release
```

Dùng để huỷ/giải phóng số L đã lấy. Sau khi giải phóng, trạng thái số thành `released` và không lấy mã OTP qua API lấy mã nữa.

Request giải phóng một số:

```json
{
  "id": "f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35"
}
```

Cũng hỗ trợ giải phóng hàng loạt:

```json
{
  "ids": [
    "f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35",
    "8d3c6f37-4d77-4c8c-b3df-2b0d6f4f9a11"
  ]
}
```

Giải thích field:

| Field | Bắt buộc | Mô tả |
| --- | --- | --- |
| `id` | Không | ID một số, tức `item.id` từ API lấy số |
| `ids` | Không | Mảng ID số hàng loạt; phải truyền ít nhất `id` hoặc `ids` |

Ví dụ request:

```sh
curl -s "http://localhost:8788/api/admin/l/release" \
  -H "Authorization: Bearer <ADMIN_AUTH_CODE>" \
  -H "Content-Type: application/json" \
  -d '{"id":"f1b8b315-8c2a-4e23-8a94-fd1c2e4a9d35"}'
```

Phản hồi thành công:

```json
{
  "updated": 1,
  "released": 1,
  "failed": []
}
```

Ví dụ phản hồi một phần thất bại:

```json
{
  "updated": 1,
  "released": 1,
  "failed": [
    {
      "id": "8d3c6f37-4d77-4c8c-b3df-2b0d6f4f9a11",
      "phone": "9091234662",
      "activationId": "67908f935ab3410bd4c7f758",
      "message": "订单不存在或已失效",
      "raw": "NO_ACTIVATION"
    }
  ]
}
```

`message` gốc `订单不存在或已失效` = đơn không tồn tại hoặc đã hết hiệu lực (`NO_ACTIVATION`).

Giải thích field phản hồi:

| Field | Mô tả |
| --- | --- |
| `updated` | Số lượng lần này cập nhật thành đã giải phóng; giải phóng lại số đã released vẫn tính thành công |
| `released` | Giống `updated`, tương thích hiển thị số lượng giải phóng ở frontend |
| `failed` | Danh sách số giải phóng thất bại; mảng rỗng nghĩa là tất cả thành công |

Lỗi thường gặp (payload gốc):

```json
{"error":"请选择号码"}
{"error":"请先配置 LikeSim API Key"}
{"error":"未找到号码"}
```

| `error` gốc | Nghĩa |
| --- | --- |
| `请选择号码` | Vui lòng chọn số |
| `请先配置 LikeSim API Key` | Hãy cấu hình LikeSim API Key trước |
| `未找到号码` | Không tìm thấy số |

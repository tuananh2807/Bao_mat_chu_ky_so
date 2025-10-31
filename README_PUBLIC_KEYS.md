## Mô tả tệp được tạo / tái tạo (mật khẩu PFX: 1234)

Tệp sau đã được tạo hoặc tái sinh trong workspace này. Mật khẩu dùng cho `cert.pfx` là `1234`.

1) `cert.pem`
- Chứng chỉ X.509 mã hóa PEM (self-signed), Subject CN="Lê Tuấn Anh".

2) `pubkey.pem`
- Khóa công khai ở định dạng PEM (SubjectPublicKeyInfo) trích từ `cert.pem`.

3) `cert.der`
- Chứng chỉ X.509 ở dạng nhị phân DER.

4) `cert.pfx`
- Gói PKCS#12 chứa khóa riêng và chứng chỉ (mật khẩu: `1234`).

## File sao lưu
- Nếu trước đó tồn tại `cert.pfx`, nó đã được đổi tên thành `cert.pfx.bak`.
- Nếu `cert.pem`, `cert.der`, `pubkey.pem` đã tồn tại, chúng được sao chép thành `*.bak` trước khi tái sinh.

## Cách sử dụng nhanh
- `ky.py` sử dụng khóa riêng trong `cert.pfx` để ký PDF. Lưu ý: các chữ ký đã tạo bằng `cert.pfx` cũ sẽ không còn xác thực được với chứng chỉ mới.
- `check_ky.py` có thể dùng `cert.pem`, `cert.der` hoặc `pubkey.pem` để kiểm tra/chứng thực chữ ký.

Ví dụ:
- Nếu một công cụ/tiện ích yêu cầu chứng chỉ ở định dạng PEM, truyền `cert.pem`.
- Nếu yêu cầu DER thì dùng `cert.der`.

## Các lệnh đã chạy (PowerShell)

Các lệnh này đã được thực hiện trong PowerShell để sao lưu tệp cũ (nếu có) và tạo khóa/chứng chỉ mới:

```powershell
# Backup (nếu có)
Rename-Item -Path cert.pfx -NewName cert.pfx.bak -ErrorAction SilentlyContinue
Copy-Item cert.pem cert.pem.bak -ErrorAction SilentlyContinue
Copy-Item cert.der cert.der.bak -ErrorAction SilentlyContinue
Copy-Item pubkey.pem pubkey.pem.bak -ErrorAction SilentlyContinue

# Tạo private key và self-signed certificate (CN = Lê Tuấn Anh), rồi đóng gói PFX
openssl genpkey -algorithm RSA -out private.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -days 3650 -key private.key -out cert.pem -subj "/CN=Lê Tuấn Anh"
openssl pkcs12 -export -out cert.pfx -inkey private.key -in cert.pem -passout pass:1234
openssl x509 -in cert.pem -outform der -out cert.der
openssl x509 -in cert.pem -pubkey -noout > pubkey.pem
```

## Ghi chú
- Chứng chỉ này là self-signed, chỉ nên dùng cho thử nghiệm hoặc demo. Để dùng trong môi trường production hoặc để chứng thực lâu dài, hãy lấy chứng chỉ do CA (Certificate Authority) cấp.
- Nếu bạn muốn thay vì tạo self-signed, tôi có thể tạo một CSR (`private.key` + `request.csr`) để bạn gửi cho CA.
- Nếu cần định dạng khóa công khai khác (ví dụ PKCS#1) hoặc muốn giữ lại chứng chỉ/khóa cũ để kiểm tra chữ ký trước đó, hãy cho biết chi tiết (tôi sẽ hướng dẫn hoặc thực hiện).

---

Nếu cần sửa thêm nội dung (thêm hướng dẫn sử dụng cụ thể cho `ky.py`/`check_ky.py`, hoặc thay mật khẩu PFX), cho tôi biết yêu cầu cụ thể và tôi sẽ cập nhật tiếp.

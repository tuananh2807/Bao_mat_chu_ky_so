# Bao_mat_chu_ky_so
Chủ đề: Chữ ký số trong file PDF 
Sinh viên thực hiện: Lê Tuấn Anh 
Mã sinh viên: K225480106001 
Lớp: 58KTPM 
Giảng viên hướng dẫn: Đỗ Duy Cốp 
Ngày nộp: 31/10/2025 
==========================================
Hình 1. Kết quả ký số file PDF  
Ảnh thể hiện quá trình thực thi chương trình ky.py để ký số cho tài liệu PDF gốc.  
Khi chạy lệnh, chương trình báo:  
“Số trang PDF gốc: 4” và “Đã ký thành công: anh_da_ky.pdf”.  
Đồng thời xác nhận “PDF hợp lệ! Số trang: 4”.   
Điều này chứng tỏ file PDF đã được chèn thành công chữ ký số, không thay đổi cấu trúc hay nội dung.  
Phía trên cửa sổ VS Code, có thể thấy file anh_da_ky.pdf hiển thị trang cuối cùng của báo cáo, trong đó xuất hiện chữ ký của em kèm thông tin ngày ký và chữ ký tay.  
→ Kết luận: Quá trình ký PDF bằng Python và chứng chỉ cá nhân đã thành công.  
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/e0b5c076-976c-445b-8f26-20afb59ee48d" />  

Hình 2. Chạy script kiểm tra chữ ký check_ky.py  
Ảnh này thể hiện kết quả khi sinh viên chạy chương trình check_ky.py để xác thực chữ ký trên file anh_da_ky.pdf.  
Kết quả in ra trong terminal gồm các dòng kiểm tra:  
/Contents & /ByteRange: HỢP LỆ  
PKCS#7 parse: HỢP LỆ  
messageDigest compare: HỢP LỆ  
Signature verify (by cert pubkey): HỢP LỆ  
Chain → trusted root CA: HỢP LỆ  
OCSP/CRL check: HỢP LỆ  
Timestamp token: KHÔNG CẦN (signature và chain OK)  
Incremental update check: HỢP LỆ  
→ Kết luận: Tất cả các bước xác minh đều hợp lệ, chứng tỏ chữ ký số trên PDF hợp pháp, không bị thay đổi và chứng chỉ đáng tin cậy.  
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/2d5a80b8-5e8d-4ddb-a864-aa8ff479bcd3" />  

Hình 3. Nội dung file nhật ký kiểm tra nhat_ky_check.txt  
Ảnh này cho thấy file nhat_ky_check.txt được tạo sau khi chạy check_ky.py.  
File ghi lại toàn bộ 8 bước xác minh với trạng thái tương ứng:  
/Contents & /ByteRange: HỢP LỆ  
PKCS#7 parse: HỢP LỆ  
messageDigest compare: HỢP LỆ  
Signature verify (by cert pubkey): HỢP LỆ  
Chain → trusted root CA: HỢP LỆ  
OCSP/CRL check: HỢP LỆ  
Timestamp token: KHÔNG CẦN  
Incremental update check: HỢP LỆ  
→ Kết luận: Nhật ký xác minh được tạo tự động, thể hiện quy trình kiểm tra chữ ký hoàn chỉnh và kết quả đều hợp lệ.  
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/2454dc49-953b-436f-b429-9b258d814d18" />   

Nhận xét cuối cùng  
Qua bài thực hành, em hiểu rõ quy trình ký và xác thực chữ ký số trong file PDF, nắm được vai trò của các thành phần như /ByteRange, /Contents, và chứng chỉ số.  
Bài giúp em củng cố kiến thức về mật mã học ứng dụng, hiểu cách chữ ký số đảm bảo toàn vẹn, xác thực và giá trị pháp lý cho tài liệu điện tử.  



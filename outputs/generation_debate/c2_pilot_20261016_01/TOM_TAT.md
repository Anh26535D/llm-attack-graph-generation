# Pilot C2: single-agent, tự sửa và multi-agent debate

Đã thực hiện **1 repeat C2**, dùng chung graph nháp và tám mô tả CVE.
Tất cả vai trò dùng Gemini `gemini-3.8-flash`; API cũng ghi nhận đúng model
này trong cả bảy request. Debate gồm các vai trò độc lập, không phải nhiều
model khác nhau. Reasoning medium, output cap 16.384 token/call, một vòng debate.

| Cách sinh | Node | Cạnh | Conditional | Unknown | Tổng token gồm reasoning | Thời gian API |
|---|---:|---:|---:|---:|---:|---:|
| Single-agent với prompt có trích nguồn | 8 | 2 | 2 | 0 | 5.048 | 28,4 giây |
| Một agent tự sửa ba lượt | 8 | 2 | 2 | 0 | 30.655 | 138,3 giây |
| Hai agent debate rồi tổng hợp | 8 | 2 | 2 | 0 | 20.684 | 81,3 giây |

Mỗi nhánh có 0 supported, 0 unsupported và 0 contradicted. Nhãn do
**validator offline hiện có** gán; không phát sinh lượt LLM validation riêng.
Conditional nghĩa là còn điều kiện cần xác minh, không phải cạnh đã được
chứng minh khả thi trên hệ thống thực tế.

Hai cạnh đều được giữ trong cả ba nhánh:

1. `CVE-2019-3562 → CVE-2020-1885`: khả năng thực thi mã trong Oculus Browser
   có thể tạo bối cảnh local user cho lỗ hổng ghi file/nâng quyền.
2. `CVE-2019-3562 → CVE-2021-24038`: khả năng thực thi mã có thể tạo process
   không đặc quyền để nhận privileged handle.

Đây là các cầu nối **có điều kiện**: chưa biết hai phần mềm có cùng host,
đúng phiên bản/nền tảng, có thoát sandbox và có quyền thao tác file/handle
cần thiết hay không. Không thể suy từ hai mô tả CVE rằng điều kiện đó đã có.

Debate không thêm/bỏ cạnh. Nó sửa cách diễn đạt hai cạnh và làm rõ điều kiện
về hard link, sandbox, process handle. Nhánh tự sửa cũng giữ nguyên hai cầu
nối. Sửa văn bản hoặc nêu thêm điều kiện chưa đủ để kết luận accuracy tăng.

**Kết quả pilot: chưa thấy cải thiện về cấu trúc graph hoặc nhãn offline.**
Debate dùng khoảng 4,1 lần tổng token của single-agent trong lượt này. Không
suy từ một repeat ra kết luận phương pháp luôn tốt hơn/kém hơn.

Tổng đã thực hiện qua API là **7 request, 46.291 token**. Draft dùng chung nên
không cộng trực tiếp ba hàng: token/calls và thời gian draft được tính vào
mỗi nhánh để so sánh, nhưng chỉ thực hiện một lần. Thời gian trong bảng là
tổng thời gian các request của nhánh, gồm draft, không tính render.
Trong tổng token có 23.840 thoughts, 16.897 input và 5.554 text output.
Không có dữ liệu chi phí tiền từ provider trong artifact này.

Đây là prompt generation mới có CVE ID, bằng chứng riêng và một node/CVE;
không phải prompt Appendix A nguyên bản. Cả ba nhánh nhận cùng schema/prompt
nháp mới. Không quy sự khác biệt với graph cũ riêng cho debate.

**Chưa có gold do người chấm độc lập: accuracy, precision và recall = N/A.**
Muốn đánh giá độ ổn định cần nhiều repeat; muốn đánh giá chất lượng ngữ nghĩa
cần chuẩn chấm độc lập, kể cả các cầu nối mà mọi nhánh đều bỏ sót.

- [Ảnh so sánh, cùng vị trí node](analysis/r01_comparison.png)
- [Chi tiết từng cạnh và điều kiện](analysis/PAIRED_COMPARISON.md)
- [Dữ liệu so sánh](analysis/paired_analysis.json)
- [Kiểm tra input không bị thay đổi](analysis/INPUT_AUDIT.json)
- [Prompt gốc của pilot](draft_prompt.txt)

Các artifact gốc, journal, raw response và ảnh riêng từng nhánh nằm trong
`runs/r01/`. Đọc báo cáo không gọi API.

# C2 mở rộng: đã chạy xong một pilot

Đã mở rộng từ graph tám node/hai cạnh của pilot trước thành **27 node trạng
thái/hành động**, với nhiều bước qua pi-lab → win-a → win-b. Dữ liệu bổ sung
là lab **mô phỏng do assistant biên soạn**, không phải môi trường thực tế hay
thông tin mới được xác nhận trong CVE. Đây là biến thể mới của C2.

| Cách sinh | Node | Cạnh | Khớp tham chiếu | Thừa | Thiếu | Tổng token provider |
|---|---:|---:|---:|---:|---:|---:|
| Single-agent | 27 | 23 | 23 | 0 | 0 | 14.836 |
| Single-agent tự sửa | 27 | 23 | 23 | 0 | 0 | 79.231 |
| Multi-agent debate | 27 | 23 | 23 | 0 | 0 | 75.130 |

Cùng model Gemini `gemini-3.8-flash`, cùng graph nháp, cùng dữ liệu và cùng
trần output 32.768 token/call, reasoning medium. Tự sửa và debate mỗi nhánh
bốn request tính cả draft; draft chỉ thực hiện một lần. Toàn bộ pilot hoàn
tất dùng bảy request riêng biệt, **139.525 token** theo provider, gồm reasoning.

**Cả ba khớp 100% tham chiếu mô phỏng về 23 quan hệ có kiểu.** Đây không phải
accuracy của project trên hệ thống thật. Node inventory đã được cho trước
để cố định độ hạt; thí nghiệm đo dựng quan hệ, không đo tự khám phá node.
Label/pre/postcondition và nội dung giải thích chưa được chuyên gia chấm.

Hai nhóm điều kiện AND đều được giữ đầy đủ. Các đối chứng âm — bản đã vá,
không physical access, default password đã đổi, không mở trang độc hại và
audio không tạo execution — không bị nối thành đường tấn công khả dụng.

**Debate không thay đổi cấu trúc graph trong pilot này.** Nó dùng khoảng
5,1 lần token của single-agent. Kết quả cho thấy bộ mô phỏng hiện tại còn
quá rõ ràng để phân biệt lợi ích của debate; tăng số node chưa đủ làm bài
thử khó hơn. Một pilot chưa đo được độ ổn định hay lợi ích tổng quát.

Ảnh dùng chung vị trí node và tên ngắn để dễ so sánh cấu trúc. Văn bản nguyên
bản do model sinh nằm trong `runs/r01/<strategy>/candidate.json`/`graph.json`.

- [Ba graph đặt cạnh nhau](analysis/r01_comparison.png)
- [Single-agent, ảnh lớn](analysis/r01_grounded.png)
- [Tự sửa, ảnh lớn](analysis/r01_self_refine.png)
- [Debate, ảnh lớn](analysis/r01_debate.png)
- [Bảng đo và quy trình đầy đủ](analysis/COMPARISON.md)
- [Kịch bản mô phỏng đầu vào](raw_scenario.txt)

Bước tiếp theo phù hợp là một tập kịch bản mới với văn bản thô, nhiều điều
kiện tương tác và không cho sẵn node inventory; chốt chuẩn chấm trước khi
sinh graph. Không chỉnh bài thử sau kết quả để buộc debate thắng.

## Lỗi kỹ thuật và phục hồi

Một lượt trước sinh JSON lặp khóa `host`: giữ nguyên lỗi (12.130 token).
Một request khác bị ngắt lúc hit limit, không có response/usage: giữ trạng
thái chưa rõ kết quả; tiến trình đã dừng. Lượt hiện tại dùng lại cùng input
của lượt bị ngắt, có bản ghi `CONTINUATION.json`.

Sau năm request của lượt mới, strict parser dừng vì Defender trả JSON trong
Markdown fence. Bản gốc `c2_extended_20261017_03` vẫn giữ kết quả lỗi. Bản
phục hồi này chỉ bóc một lớp Markdown bao trọn JSON, áp dụng cùng quy tắc cho
mọi stage; không sửa JSON hay nội dung. Đã dùng lại năm response và chỉ gọi
hai request còn thiếu. `FORMAT_RECOVERY.json` ghi thay đổi giao thức; không
coi đây là batch pass strict-format ban đầu. Hash input/response gốc được
kiểm tra không thay đổi. Một stage thực tế cần bóc fence: Defender.

Không cộng đôi token/request giữa thư mục gốc và thư mục phục hồi. Tính cả
lượt JSON lỗi trước đó, số token provider đã biết là **151.655**, cộng phần
chưa rõ usage của request bị ngắt. Không có số tiền chi phí từ provider.

Code đã kiểm tra bằng **245 tests pass**, không gọi API trong tests.

# C2 mở rộng: nhiều trạng thái và hành động hơn

C2 cũ có một node/CVE nên cố định tám node. Biến thể mới dùng **27 node
trạng thái/hành động**, cùng tám mô tả CVE, cộng dữ liệu lab **mô phỏng do
assistant biên soạn**. Nó thay đổi cả input và độ hạt, không phải cùng C2
nguyên bản. Không diễn giải số cạnh tăng là tác dụng của debate.

Node inventory được cung cấp trước để ba nhánh so sánh cùng độ hạt. Thử
nghiệm này chủ yếu đo việc dựng các quan hệ giữa node, không đo khả năng tự
khám phá node từ báo cáo tự do. Label/pre/postcondition và các cạnh do LLM sinh.

Luồng chính: credential piSignage → đọc file → credential RaspAP → thực thi
ở pi-lab → đọc credential win-a → đăng nhập win-a → hai nhánh nâng quyền →
đọc secret cho win-b → đăng nhập từ win-a → nâng quyền win-b.

Các cầu nối mới như credential lưu trong config, quyền đọc file, topology,
quyền sau khai thác là giả định công khai của lab, **không nằm sẵn trong CVE**.
Không có khai thác hay đăng nhập hệ thống thật trong experiment.

Graph hai loại node: state → action (`requires`), action → state (`produces`).
Các input vào cùng action có nghĩa **AND**. Hai action cùng sinh một state
là hai lựa chọn; không có nghĩa phải thực hiện cả hai. Không thêm cạnh bắc
cầu hoặc cạnh chỉ biểu diễn thứ tự thời gian.

Lab có các đối chứng âm: bản đã vá, không có physical/PCI access, default
password đã đổi, victim không mở trang độc hại, audio không tạo execution.
Theo quy ước graph các transition khả dụng, action bị chặn vẫn giữ node
nhưng không có cạnh. Không dùng quy ước này cho mọi loại attack graph khác.

`reference.synthetic.json` định nghĩa trước **23 quan hệ tức thời** và hai
nhóm AND. File này được đóng băng trước generation, tách khỏi prompt. Chấm
precision/recall/F1 là **mức khớp tham chiếu mô phỏng**, không phải nhãn chuyên
gia độc lập hay accuracy của project trên lỗ hổng ngoài thực tế. Chấm cặp
node + relation, không chứng minh toàn bộ câu chữ label/pre/postcondition.
Không áp dụng validator CVE cũ vào node trạng thái rồi gọi chúng là unknown.

Ba nhánh vẫn dùng chung draft, nguồn và model: grounded / tự sửa / debate.
Một repeat cả ba nhánh tối đa 7 request. Output cap mặc định 32.768 để chứa
graph và bằng chứng dài hơn; reasoning medium. Không tự retry hoặc nới cap.

```powershell
.\.venv\Scripts\python.exe scripts/run_scenario_debate.py prepare --out outputs/generation_debate/c2_extended_01 --repeats 1
.\.venv\Scripts\python.exe scripts/run_scenario_debate.py execute --out outputs/generation_debate/c2_extended_01
```

Prepare không gọi API. Execute mới gọi. Đọc `raw_scenario.txt`, `scenario.json`,
`draft_prompt.txt`, `manifest.json` để kiểm tra input và ngân sách. Reference
không được truyền cho bất kỳ agent nào; engine chỉ nhận node descriptions.
Mỗi cạnh được giữ phải có quote nguyên văn của hai endpoint. Kiểm tra quote
chỉ xác nhận văn bản nguồn, không xác nhận quan hệ.

Sau thay đổi engine, source hash của pilot C2 cũ khác working tree. Raw
response/graph cũ được giữ; code snapshot đúng hash trước thay đổi nằm trong
`outputs/generation_debate/c2_pilot_20261016_01/code_snapshot`. Không sửa hash
manifest cũ để ép chạy lại bằng code mới.

## Ảnh và bảng so sánh

Sau khi execute xong, tạo report/ảnh mà không gọi thêm API:

```powershell
.\.venv\Scripts\python.exe scripts/compare_scenario_debate.py --out outputs/generation_debate/c2_extended_01
```

`analysis/COMPARISON.md` ghi số cạnh khớp/thừa/thiếu, hai nhóm AND và lỗi nối
đối chứng âm. `analysis/r01_comparison.png` đặt các graph cạnh nhau, cùng tên
ngắn và vị trí node. Mỗi nhánh có thêm PNG/SVG riêng để đọc rõ. Tên ngắn trên
ảnh được lấy từ fixture cho nhất quán; văn bản đầy đủ do model sinh giữ trong
`runs/r01/<strategy>/candidate.json` và `graph.json`.

Các nhãn xanh/đỏ/vàng thể hiện quan hệ khớp/thừa/thiếu so với tham chiếu mô
phỏng; không phải năm tag của validator CVE cũ. Tham chiếu chỉ chấm quan hệ
có kiểu và endpoint, không chấm toàn bộ ngữ nghĩa của label/pre/postcondition.
Ảnh có nét chấm cho quan hệ tham chiếu bị bỏ sót là lớp so sánh thêm vào,
không phải cạnh model đã sinh.

Số node/cạnh lớn hơn chưa bảo đảm benchmark khó hơn. Khi inventory, bước đi
và điều kiện được viết quá rõ, single-agent có thể đạt tối đa ngay từ draft.
Nếu muốn đo lợi ích thực của debate, bước kế tiếp nên là một tập kịch bản mới
định trước với nguồn thô, bố cục khác nhau và điều kiện tương tác, rồi chấm
mù độc lập. Không chỉnh benchmark sau khi xem kết quả để ép debate thắng.

## Phục hồi riêng lỗi bọc Markdown

Nếu model trả JSON hợp lệ nhưng bọc cả response trong một khối Markdown,
strict run vẫn ghi lỗi. Có thể tạo **một bản phục hồi riêng**, dùng lại các
response đã nhận và chỉ bóc lớp bọc, không sửa JSON hay nội dung:

```powershell
.\.venv\Scripts\python.exe scripts/resume_scenario_format.py --source STRICT_RUN --out RECOVERED_RUN
```

Lệnh kiểm tra source không còn lock và tất cả request đã nhận đủ response,
không truncation. Request `started`/`error` không được tự gửi lại. Tối đa các
stage còn thiếu trong ngân sách ban đầu mới được gọi. Original không thay đổi.
`FORMAT_RECOVERY.json` ghi thay đổi giao thức và hash input/script; các raw
response vẫn giữ nguyên. Normalization áp dụng giống nhau cho mọi stage,
chỉ nhận một lớp fence bao trọn response; prose, duplicate key và JSON bị
cắt vẫn bị từ chối. Báo cáo phải tách lỗi strict-format khỏi kết quả sau
normalization, không ghi cả batch ban đầu là thành công về định dạng.

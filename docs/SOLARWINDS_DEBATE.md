# SolarWinds theo input của bài gốc + multi-agent debate

Thí nghiệm dùng lại **threat report trong bài báo**, tách khỏi C2 mô phỏng.

| Case | Input | Hình trong bài |
|---|---|---|
| T1 | Toàn bộ Appendix C.1 SolarWinds report | Figure 2 |
| T2 | Appendix C.2, đoạn về evasion | Figure 8 |

Các file trong `data/reproduction/` đã trích và chuẩn hóa ngắt dòng/ký tự từ
PDF. `manifest.json` ghi hash, trang nguồn và các bước chuẩn hóa. Loader
kiểm hash trước khi dùng. Đợt đầu chạy T1, không thay T1 bằng excerpt T2.

## Thiết kế

**Baseline** gửi đúng prompt đã lưu của bài, không thêm instruction generation
mới, không thêm node inventory, host, credential hoặc CVE từ nguồn khác.
LLM tự quyết định số node/cạnh. Đây là tái hiện input/phương pháp với model
hiện tại; không phải tái tạo đúng output GPT-4 trong paper.

Ba nhánh dùng cùng graph baseline:

- `single`: graph nguyên bản sau parse, không chỉnh sửa.
- `self_refine`: cùng model tự đối chiếu nguồn và sửa ba lần.
- `debate`: một vai trò bảo vệ những chi tiết/quan hệ có căn cứ, một vai trò
  phản biện quan hệ thiếu căn cứ và tìm nội dung bị bỏ sót; editor tổng hợp
  bằng báo cáo nguồn. Hai bên không xem phản biện hiện tại của nhau.

Mỗi nhánh refinement/debate có bốn calls tính cả draft, cùng output cap và
mức reasoning. Cùng calls/cap không đồng nghĩa cùng input/actual tokens.
Một repeat cả ba nhánh tốn tối đa bảy request riêng biệt. Mặc định một pilot;
để đo ổn định có thể chuẩn bị run riêng với 10 repeats trước khi execute.

Các vai trò dùng cùng model nhằm tránh trộn hiệu ứng thay model với debate.
Multi-agent ở đây là các vai trò/prompt độc lập, không mặc định nhiều model.
Critic không bắt buộc bất đồng, editor không lấy đồng thuận làm bằng chứng.

## Nội dung cần phản biện

Tập trung vào những sai lệch threat-report thường gặp:

- Biến nhiều capability/technique thành một chuỗi thời gian bắt buộc.
- Biến TEARDROP được quan sát ít nhất một lần thành bước của mọi nạn nhân.
- Bỏ chữ “potentially”, “likely”, “we believe” hoặc điều kiện cần.
- Gộp SUNBURST, TEARDROP và BEACON thành cùng thành phần.
- Nhầm DNS discovery với HTTP C2; condition check với compromise đã xảy ra.
- Nhầm detection/mitigation của defender với action của attacker.
- Thêm host/credentials/exploit hoặc nối quan hệ chỉ vì hai đoạn đứng cạnh nhau.

Report được tách **theo paragraph nguyên bản** để gán locator P001…P056 cho
T1. Đây chỉ là chỉ mục trích dẫn, không phải các node cho trước. Reviewer
chọn tối đa 12 findings và 6 omissions, mỗi lý do tối đa 90 từ; không phải
audit toàn bộ cạnh. Citation phải là substring nguyên văn trong đúng đoạn,
không quá 350 ký tự. Quote sai được đánh dấu và không đưa nguyên văn vào
bằng chứng cho editor. Quote đúng văn bản vẫn chưa chứng minh entailment.

Editor có thể sửa node/cạnh hoặc thêm nội dung bị bỏ sót, giữ ID cho concept
không đổi. Sidecar `changes` lưu lý do và trích dẫn. Code tính diff từ graph
thực, không lấy lời model nói “đã sửa” thay cho sự thay đổi thật.

## Chạy

```powershell
.\.venv\Scripts\python.exe scripts/run_report_debate.py prepare --out outputs/generation_debate/solarwinds_T1_01 --case T1 --repeats 1 --backend gemini
.\.venv\Scripts\python.exe scripts/run_report_debate.py execute --out outputs/generation_debate/solarwinds_T1_01
.\.venv\Scripts\python.exe scripts/compare_report_debate.py --out outputs/generation_debate/solarwinds_T1_01
```

Prepare không gọi API. Execute mới gọi. Report/compare chỉ đọc kết quả, không
gọi thêm API. `--repeat-ids 1` cho phép chạy từng repeat trong run đã chốt.
T2 dùng `--case T2` với thư mục riêng. Không trộn T1/T2 thành hai repeat cùng
prompt. Token cap mặc định 32.768, reasoning medium, không tự tăng cap/retry.

Model/provider, prompt/report/paragraphs/code được cố định bằng hash. Raw
response và journal lưu trước khi parse. Resume dùng lại received response,
không tự gọi lại stage error/started chưa rõ chi phí. Một whole-response
Markdown JSON fence được chấp nhận giống nhau ở tất cả stage, ghi riêng
strict/fenced; không sửa JSON bị cắt hoặc duplicate keys.

## Đánh giá

Không chạy validator tám CVE lên graph SolarWinds rồi đếm unknown. T1/T2 là
graph sự kiện/quan hệ threat report, cần khung chấm riêng dựa vào báo cáo.
Không lấy hình paper làm danh sách đầy đủ tuyệt đối mọi cạnh phải có.

Tự động báo: parse/schema, số node/cạnh, node và cặp cạnh thêm/bỏ, sửa nội
dung, quote verification, latency và token usage. Giữ đầy đủ các lỗi/partial.
Diff dựa trên ID: đổi tên/tách/gộp node cần người đọc align, không phải lỗi
ngữ nghĩa mặc định. Node/edge nhiều hơn cũng không phải chất lượng cao hơn.

Khi chưa có người chấm độc lập, accuracy/precision/recall/F1 để **N/A**.
`annotation_source_blind.json` dành để người đọc tạo danh sách claim/coverage
theo nguồn trước khi nhìn graph. `runs/rNN/<strategy>/annotation_blind.json`
chứa graph và nguồn, không chứa lời reviewer hay gợi ý nhãn.

Người chấm cần xét cả độ đúng của quan hệ và nội dung bị bỏ sót, giữ phạm vi,
alternatives và uncertainty. Có thể dùng năm nhãn như một rubric chấm bằng
tay, không tự coi chúng là kết quả validator CVE. Nên có hai người chấm và
giải quyết bất đồng; đánh giá theo paired repeat, không coi cạnh trong cùng
graph là các repeat độc lập. Một pilot chưa chứng minh lợi ích tổng quát.

`analysis/index.html` hiển thị graph có zoom/kéo và tooltip node/cạnh; kèm
Figure 2/8 tham chiếu trong bài. PNG/SVG dùng chung vị trí node và display
code để so cấu trúc, tên đầy đủ trong `node_legend.csv`. Xanh lá là pair/node
thêm so với baseline, không phải nhãn “đúng”. Không thay graph model bằng
graph gộp hay khung node tự biên để làm ảnh giống paper.

# Báo cáo tái hiện CrystalBall §5.1–5.4

Ngày tổng hợp: 27/09/2026. Run: `20260927_full_reproduction`.

**Phạm vi chia sẻ:** repo cung cấp code, dữ liệu nguồn và báo cáo tổng hợp này. Raw response, journal, worksheet và báo cáo chi tiết của run được giữ cục bộ tại `outputs/experiments/20260927_full_reproduction/`, không có trong bản clone. Những đường dẫn bằng chứng dưới đây tính từ thư mục run đó, trừ khi ghi rõ `docs/archive/`; muốn kiểm toán số liệu lịch sử cần xin bộ artifact từ người phụ trách.

**Đã hoàn tất các request theo thiết kế đã chốt và đánh giá lại offline.** Kết quả hỗ trợ việc tái hiện quy trình sinh graph với hai mô hình thay thế, nhưng chưa chứng minh graph hoàn chỉnh hoặc mô hình nào tốt hơn. Báo cáo này thay phần tổng hợp cũ tại thư mục gốc, dùng số liệu sau sửa parser và các worksheet đã đọc lại. Raw response, prompt, journal và Review 3 gốc được giữ nguyên.

Nhãn ngữ nghĩa là **Codex sơ bộ, không phải xác nhận chuyên gia**. Review 3 của run gốc là `approved`; manifest đánh giá lại vẫn lưu `awaiting_user_review`. Việc bàn giao tài liệu không tự sửa trạng thái review trong artifact hay nâng mức xác nhận của nhãn.

## 1. Mục tiêu và phạm vi

Tái hiện phương pháp và các nhóm thí nghiệm §5.1–5.4 của [Using Retriever Augmented Large Language Models for Attack Graph Generation](https://arxiv.org/abs/2408.05855): baseline, graph từ CVE context, graph từ threat report, chia/gộp, tiếp tục và mở rộng graph. Dùng Gemini `gemini-3.8-flash` và GPT-5.6 Luna qua OpenRouter `openai/gpt-5.6-luna`, thay cho mô hình trong bài gốc. Kết quả không phải phép lặp nguyên trạng các con số của bài báo.

Phạm vi bổ sung chỉ có X0 dùng instruction/schema tương ứng. Tuy nhiên prompt X0 thực tế bỏ cả mô tả hệ thống mục tiêu; vì vậy chưa đạt một đối chứng giữ mọi yếu tố ngoài context như nhau. Không chạy thêm API để sửa thiết kế hồi tố.

## 2. Dữ liệu, cấu hình và thiết kế

| Thành phần | Cấu hình thực tế |
|---|---|
| Dữ liệu CVE | Tám record chính thức, corpus nhỏ theo case study; không có tập distractor |
| Nguồn CVE | CVEProject/cvelistV5, commit `73ca210d8ac127ab434175fe2a8a050d3c8844d0` |
| Query retrieval | Oculus Desktop, Jetson TX1, Raspberry Pi |
| Extraction | LLM Gemini; tái sử dụng index chính thức đã dựng trước đó |
| Embedding | `facebook/contriever-msmarco`, 768 chiều |
| Ngưỡng retrieval | `MIN_SIMILARITY=0.68` |
| Context budget | `CONTEXT_TOKENS_PER_QUERY=3750`; bộ ước lượng theo từ trong môi trường run |
| Lặp | 5 lần cho mỗi model × điều kiện |
| Prompt | Bytes/hash cố định giữa hai model và các repeat của cùng điều kiện chính |
| Generation | Reasoning/thinking low; không khóa temperature/seed để có tái lập ngẫu nhiên tuyệt đối |
| Output cap chính | T1: 8192; C0/C1/C2/T0/T2/X0: 4096 |
| Ngân sách đợt đã chạy | 50.000 VND; không có extraction mới trong đợt này |

[Manifest CVE](data/cve_official/manifest.json) chứa URL và hash từng record. CVE piSignage đúng là `CVE-2019-20354`, thay ID sai `CVE-2020-25299` của dữ liệu demo cũ. Dữ liệu `data/cve_samples/` và ví dụ viết tay không được tính là output thí nghiệm chính.

[Manifest Appendix](data/reproduction/manifest.json) mô tả trang nguồn và chuẩn hóa văn bản. C2/T0/T1/T2 dùng prompt từ Appendix A/B/C.1/C.2; T1 dùng toàn bộ văn bản đã trích, không dùng report demo rút gọn.

| Điều kiện / nhóm | Nội dung | Request |
|---|---|---:|
| C0 | Prompt no-context theo §5.1 với Raspberry Pi, Oculus Desktop, NVIDIA Jetson Nano | 10 |
| C1 | Prompt có context truy hồi bằng query Oculus Desktop, Jetson TX1, Raspberry Pi | 10 |
| C2 | Appendix A, đủ tám mô tả CVE theo thứ tự nguồn | 10 |
| T0 | Appendix B, hai nhánh PostgreSQL và container/application RCE | 10 |
| T1 | SolarWinds, Appendix C.1 đầy đủ | 10 |
| T2 | SolarWinds evasion, Appendix C.2 | 10 |
| X0 | Instruction/schema nhưng thiếu cả CVE context và target system | 10 |
| §5.4 chia/gộp | Hai chunk × hai model × năm repeat; merge cục bộ | 20 |
| §5.4 tiếp tục | Cutoff 512 token rồi continuation 4096 token | 20 |
| §5.4 mở rộng | Edge detail 4096 token và edge context 2048 token | 20 |
| **Tổng** | **70 request chính + 60 request §5.4** | **130** |

Pilot gồm hai request C1 đã nằm trong 70 request chính. Tổng 65 request mỗi model; không có retry hoặc API error trong run đã lưu.

## 3. Cách đánh giá

Tách riêng bốn lớp: request/parse; schema và cấu trúc; sự kiện; ngữ nghĩa quan hệ/path. Parse thành công không chứng minh đúng schema; schema đúng không chứng minh đúng nội dung. JSON sửa do bị cắt và finish reason chạm cap là hai trường độc lập.

Schema chuẩn của repo yêu cầu các trường node/edge như `id`, `label`, `from`, `to` và pre/postcondition khi áp dụng. C0/T0 không yêu cầu đầy đủ chuẩn này trong prompt; raw-schema 0/5 không đồng nghĩa chúng không sinh được graph. Parser có thể lấy graph trong wrapper `attack_graph`, nhưng không vì vậy mà nâng raw-schema thành pass.

Chấm ngữ nghĩa theo quyết định lấy mẫu (`offline_reevaluation/manual_review_decision.md`, lưu cục bộ):

- **T0:** đọc toàn bộ 10 output × 2 nhánh = 20 nhánh.
- **C1/C2:** sáu nhóm quan hệ × hai model × hai điều kiện = 24 stratum. Trong mỗi stratum, chọn occurrence có repeat nhỏ nhất, rồi edge index nhỏ nhất; ghi thiếu nếu không có. Khi outcome nằm trong postcondition, chấm event tại node và ghi edge riêng là N/A.
- **T1/T2:** bắt đầu ở r01 cho 28 stratum sự kiện × model × điều kiện; mở rộng đủ năm repeat ở bảy stratum có chỉ báo tự động biến thiên, tổng 56 quan sát event-output.

Mẫu SolarWinds không cân bằng và không ngẫu nhiên. Các số đếm thủ công chỉ mô tả mẫu được đọc; không dùng làm accuracy toàn bộ graph, kiểm định thống kê hay xếp hạng model.

## 4. Kết quả kỹ thuật sau đánh giá lại

130/130 request có response lưu, 0 API error. Trong đó 120 response cần parse JSON/graph và 10 response edge-context là văn bản.

| Parse mode | Số response |
|---|---:|
| `raw_json` | 73 |
| `markdown_stripped` | 22 |
| `repaired_truncated` | 22 |
| `parse_failed` | 3 |
| `not_applicable` — edge-context dạng văn bản | 10 |
| **Tổng** | **130** |

95 output parse không cần sửa JSON; 22 cần repair; 3 parse thất bại. Nhãn `strict_success` trong metrics chỉ nói về parse, không phải thành công ngữ nghĩa.

### Cấu trúc bảy điều kiện chính

Nguồn: metrics đã parse lại (`offline_reevaluation/metrics.json`, lưu cục bộ). Mỗi hàng có 5 output; node/edge là trung bình [min–max]. Các graph đã repair vẫn có mặt trong thống kê; riêng Luna T1 r01/r02 và T2 r03 bị truncation.

| Điều kiện | Model | Raw-schema | Node trung bình [min–max] | Edge trung bình [min–max] |
|---|---|---:|---:|---:|
| C0 | Gemini | 0/5 | 6,8 [5–9] | 6,6 [5–9] |
| C0 | Luna | 0/5 | 10,8 [6–15] | 20,6 [15–24] |
| C1 | Gemini | 5/5 | 8,2 [8–9] | 6,8 [6–8] |
| C1 | Luna | 5/5 | 10,2 [7–15] | 6,8 [3–10] |
| C2 | Gemini | 5/5 | 8,0 [8–8] | 5,2 [4–6] |
| C2 | Luna | 4/5 | 10,8 [8–17] | 10,2 [6–13] |
| T0 | Gemini | 0/5 | 9,6 [9–10] | 9,6 [9–10] |
| T0 | Luna | 0/5 | 16,2 [15–17] | 19,8 [18–21] |
| T1 | Gemini | 5/5 | 27,4 [18–33] | 28,4 [20–32] |
| T1 | Luna | 5/5 | 103,8 [89–115] | 104,6 [89–118] |
| T2 | Gemini | 5/5 | 18,6 [16–22] | 20,2 [17–25] |
| T2 | Luna | 5/5 | 59,8 [49–69] | 70,4 [62–82] |
| X0 | Gemini | 1/5 | 0,6 [0–3] | 0,4 [0–2] |
| X0 | Luna | 0/5 | 0,0 [0–0] | 0,0 [0–0] |

Số node/edge thể hiện kích thước output, không phải điểm chất lượng. X0 có 4/5 Gemini và 5/5 Luna là graph rỗng thật. Kết quả này chỉ áp dụng cho cấu hình thiếu cả context và mô tả hệ thống mục tiêu.

### Retrieval và quan hệ CVE

C1 truy hồi 7/8 CVE trong corpus case study. `CVE-2022-21819` không được lấy: metadata Jetson Linux so với query Jetson TX1 có cosine khoảng 0,632; platform NVIDIA Jetson khoảng 0,644, đều dưới 0,68. Record còn mô tả Jetson Nano/Nano 2GB, không trực tiếp xác lập ảnh hưởng lên TX1. Đây là giới hạn của query/metadata và ánh xạ case study; 7/8 không phải recall trên một corpus thực tế rộng hơn.

Worksheet CVE (`offline_reevaluation/manual_review_cve.md`, lưu cục bộ) cho thấy:

- Default password Raspberry Pi → administrator được nguồn hỗ trợ và graph biểu diễn đúng 4/4 stratum. Heuristic cũ bỏ sót khi outcome nằm trong node.
- Ngoài quan hệ trên, 20 stratum edge/topology gồm 3 được hỗ trợ, 10 có điều kiện, 2 không được hỗ trợ và 5 thiếu edge/event.
- RaspAP command execution có mặt 4/4, nhưng nguồn không tự chứng minh root/admin. Hai bridge RaspAP → Glowworm không có bằng chứng nguồn; điều kiện tấn công vật lý của Glowworm phải được giữ.
- Browser → OVRRedir cần điều kiện thực thi cục bộ trên cùng host Windows và hardlink; piSignage → RaspAP cần bằng chứng file lộ chứa auth material dùng được.
- Jetson xuất hiện đúng lõi ở 2/2 stratum C2 có context. Việc không có trong C1 không được quy là model bỏ sót input.

### T0 — hai nhánh Appendix B

Parser cũ bỏ wrapper `attack_graph`, khiến T0 Gemini bị báo nhầm rỗng và Luna bị thiếu graph. Sau sửa, **10/10 output có graph; 20/20 nhánh đúng sự kiện lõi và có path có hướng liên tục** theo worksheet sơ bộ.

Với PostgreSQL: 7 graph mô tả route kết hợp trust-auth + permitted/broad IP; 2 graph dùng broad-IP làm prerequisite reachability; 1 graph có hai prerequisite hội tụ, không được mặc định là AND. Nguồn không xác lập conjunction bắt buộc hay co-location trên mọi target.

Với container-RCE: 10/10 có đủ bốn ứng dụng và chuỗi lõi, kể cả khi tên ứng dụng nằm trong `description/details`. Vẫn phải giữ điều kiện vulnerable instance/version, reachability, isolation/privileges và phân biệt outcome mạnh hơn “server access”.

T0 là case study Appendix B mà bài báo gọi là Kubernetes. Dữ liệu hiện chỉ chấm hai nhánh PostgreSQL/container có trong prompt; không chứng minh đã đánh giá cơ chế Kubernetes đặc thù. Xem census T0 (`offline_reevaluation/manual_review_t0.md`, lưu cục bộ).

### SolarWinds

Trên **56 quan sát event-output đã chọn**, chấm thủ công có **39 đúng, 14 một phần, 3 không có**. Chỉ báo từ khóa dương 41/56; hai loại số liệu khác nhau vì dò từ khóa có thể bỏ sót diễn đạt tương đương hoặc chấp nhận mô tả chưa đủ.

Bảy sự kiện được xét liên quan đến credentials, TEARDROP/BEACON, hostname, hạ tầng cùng quốc gia, lateral credentials khác remote access, thao tác file/task và dọn công cụ. Mẫu không xác nhận toàn bộ attack path hay completeness của graph. Xem worksheet SolarWinds (`offline_reevaluation/manual_review_solarwinds.md`, lưu cục bộ).

### §5.4 — chia/gộp, tiếp tục và mở rộng

| Hạng mục | Quan sát | Diễn giải được phép |
|---|---|---|
| Chunk | Luna bị cắt 10/10; Gemini 2/10 | Token cap ảnh hưởng trực tiếp output; không kết luận chất lượng từ kích thước |
| Cutoff | 10/10 chạm cap; 7 repair được, 3 parse thất bại | Dữ liệu bị cắt dù có thể parse một phần |
| Continuation | 10/10 parse không cần repair; một Luna không đạt raw-schema | Hoàn thành bước xử lý, chưa chứng minh đã khôi phục đầy đủ graph |
| Merge | Tạo 10/10 file; đổi tên 264 ID collision; không có cross-chunk edge | Hợp các mảnh graph, chưa phải graph hoàn chỉnh hoặc path xuyên chunk |
| Edge context | 10/10 response nói nguồn không thiết lập prerequisite Browser → OVRRedir | Hỗ trợ nhãn “có điều kiện” ở quan hệ được hỏi, không xác nhận mọi cạnh khác |

Chi tiết: s54_review.md (`offline_reevaluation/s54_review.md`, lưu cục bộ). Việc đã chạy đủ các thao tác §5.4 phải được phân biệt với việc chứng minh chúng giải quyết được vấn đề completeness.

## 5. Chi phí và tính toàn vẹn

Chi phí run ước tính **15.894,68 VND** (0,60736244 USD), trong trần 50.000 VND đã duyệt. Tỷ giá lưu là 26.170 VND/USD; ưu tiên cost do provider trả về, nếu thiếu dùng token usage và bảng giá cố định trong runner. Đây không phải đối soát hóa đơn và không bao gồm chi phí dựng index trước run.

Snapshot toàn bộ nguồn gốc tại thời điểm đánh giá lại: **599 file**, SHA-256 `3bd83e4152add79b72fb5357b14d4da459e51cd3a65c2f2049e4bebd01a23678`. Xem cách ghi trong manifest đánh giá lại (`offline_reevaluation/manifest.json`, lưu cục bộ). Snapshot này mô tả tập file gốc, không phải commit hash Git.

Kiểm chứng code: **79 tests passed**, compile `src` và `scripts` thành công. Kiểm thử code và hash không chứng minh tính đúng của các quan hệ tấn công.

## 6. Những kết luận đã sửa

| Kết luận cũ | Kết luận hiện tại |
|---|---|
| T0 Gemini rỗng; Luna chỉ có trung bình 3 node / 3,6 edge | Lỗi parser wrapper; cả 10 graph không rỗng, số liệu đúng nằm ở bảng trên |
| Một số T0 thiếu tên ứng dụng | Tên nằm trong description/details; cả 10 có đủ bốn ứng dụng và chuỗi lõi |
| Cả 10 PostgreSQL sai vì AND | Phân biệt 7 route kết hợp, 2 prerequisite reachability, 1 hội tụ; giữ caveat nguồn |
| 22 output repaired là object extraction | 22/22 là JSON bị cắt đã được repair |
| Heuristic 2.131 cạnh là đánh giá ngữ nghĩa hoàn chỉnh | Chỉ là artifact lịch sử; có false negative và 1.979 cạnh “chưa rõ” |
| Parse/merge thành công chứng minh graph hoàn chỉnh | Chỉ xác nhận thao tác/cấu trúc; vẫn thiếu cross-chunk edge và bằng chứng completeness |
| X0 đo riêng tác dụng context | X0 thiếu cả context và target system; không cô lập hiệu ứng context |

Bảng trước/sau (`offline_reevaluation/before_after.md`, lưu cục bộ) và báo cáo offline chi tiết (`offline_reevaluation/REPORT.md`, lưu cục bộ) giữ bằng chứng sửa. Báo cáo/metrics tại root của run và review log (`docs/archive/REPRODUCTION_REVIEW.md`, lưu cục bộ) được giữ nguyên như lịch sử, không dùng các kết luận đã rút lại.

## 7. Kết luận và việc còn lại

Có thể sử dụng repo cho báo cáo/demo **tái hiện quy trình với mô hình thay thế**, kèm kết quả cấu trúc và chấm sơ bộ trong phạm vi mẫu đã nêu. Chưa có cơ sở khẳng định tái hiện chính xác kết quả bài gốc, xếp hạng hai model, đo riêng tác dụng context, hay xác nhận graph/path đầy đủ.

Không cần chạy thêm API để bàn giao hiện tại. Nếu nhóm cần nâng mức kết luận nghiên cứu, người phụ trách phải quyết định trước: thiết kế đối chứng giữ nguyên target system, cách xử lý truncation, phạm vi kiểm tra cross-chunk path hoặc chuyên gia xác nhận nhãn. Các bước đó là phạm vi mới, chưa được thực hiện hay tính vào số liệu này.

Hướng dẫn chạy và đánh giá cho thành viên mới nằm trong [README](README.md). Khi trình bày, luôn ghi run ID, điều kiện, model thay thế, số repeat, mẫu được chấm và giới hạn; không gọi tỷ lệ từ khóa là “độ chính xác”.

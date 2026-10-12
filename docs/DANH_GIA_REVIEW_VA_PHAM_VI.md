# Đánh giá review và phạm vi dừng hợp lý

Ngày kiểm tra: 28/09/2026. Code được kiểm tra: commit `5b129b9`. Run lịch sử: `20260927_full_reproduction`. Đây là đánh giá local cho mục tiêu học, hiểu và trình bày một dự án tái hiện bài báo.

**Cập nhật phạm vi ngày 13/10/2026:** nhóm đã chọn bổ sung DeepSeek làm mô hình thứ ba để thí nghiệm cùng Gemini và GPT-5.6 Luna. Khuyến nghị giữ phạm vi và chưa thêm model bên dưới thuộc lần review 28/09, không còn là kế hoạch hiện tại. Xem [thí nghiệm ba mô hình](THI_NGHIEM_BA_MO_HINH.md) cho trạng thái code, cách demo và thiết kế mới. Các kiểm chứng 79 tests/130 response dưới đây là bằng chứng tại thời điểm review, không phải kết quả ba mô hình.

## 1. Kết luận

**Review nhìn chung đúng về giới hạn bằng chứng. Dự án hiện tại đủ để chuyển sang học và đọc code nếu mục tiêu là tái hiện phương pháp CrystalBall và minh họa các nhóm thí nghiệm bằng mô hình thay thế.** Chưa đủ để tuyên bố xác nhận toàn bộ kết luận nghiên cứu, xếp hạng mô hình hoặc chứng minh attack graph đầy đủ và đúng trên hệ thống thực.

Không có rubric môn học hay yêu cầu riêng của giảng viên trong đầu vào; “đủ” ở đây là nhận định theo phạm vi người học vừa sức, không phải cam kết điểm hoặc nghiệm thu. Nếu đề bài bắt buộc chứng minh lợi ích RAG bằng đối chứng, phần đó vẫn còn thiếu.

Không nên biến toàn bộ đề xuất cuối review thành danh sách bắt buộc. Tại thời điểm review 28/09, hướng đề xuất là giữ nguyên phạm vi, hiểu pipeline, tự đọc một graph và biết bảo vệ giới hạn kết luận. Kế hoạch bổ sung mô hình thứ ba hiện được mô tả trong tài liệu cập nhật ở đầu trang.

## 2. Đã kiểm chứng tới đâu?

Khác với review chỉ có bản Git, lần này có bộ bằng chứng local. Tôi đã:

- Đọc PDF được cung cấp, tập trung §3–5.4, Figure 5–7, Figure 11–13 và Appendix; đối chiếu các hàm xử lý tương ứng.
- Chạy lại toàn bộ test: **79 passed**.
- Kiểm tra SHA-256: PDF, bốn file Appendix và tám CVE đều khớp manifest local. Điều này xác nhận tính nhất quán với manifest, không phải một lần tải và xác thực nguồn trực tuyến mới.
- Kiểm tra đủ **130 raw response**, hash của cả prompt và response khớp với cả **130 journal**.
- Parse lại 120 response graph bằng parser hiện hành; 10 response edge-context là văn bản. Kết quả: **73 raw_json, 22 markdown_stripped, 22 repaired_truncated, 3 parse_failed, 10 not_applicable**.
- Đối chiếu các trường parse mode, schema, JSON nguyên bản, node/edge count và repair với `offline_reevaluation/metrics.json`: không thấy chênh lệch trong các trường đã kiểm tra.
- Xác nhận cả 10 T0 đều có graph; xác nhận 13 response đã repair vẫn có `schema_valid=True`, trong đó có Luna T1 r01/r02 và T2 r03.
- Đọc thiết kế lấy mẫu và các worksheet CVE/SolarWinds. **Không chấm lại độc lập toàn bộ ngữ nghĩa của 130 response**; các kết quả 20/20 nhánh T0 và 39/14/3 SolarWinds vẫn là nhãn sơ bộ từ worksheet cũ, không được nâng thành xác nhận chuyên gia.

Việc parse lại dùng code hiện hành trong repo: đây là kiểm tra khả năng tính lại số liệu từ raw, không phải một bộ parser độc lập để chứng minh parser không có lỗi.

## 3. Nhận xét nào đúng, nhận xét nào cần thêm sắc thái?

| Nội dung review | Đánh giá sau đối chiếu |
|---|---|
| Đã tái hiện pipeline, chưa xác nhận mọi kết luận của paper | Đúng. Algorithm 1/2/3 lần lượt có trong `preprocess.py`, `retriever.py`, `generator.py`; hậu xử lý ở `postprocess.py`. |
| C0/C1 và X0 chưa cô lập tác dụng context | Đúng. C0/C1 thay cả instruction và cách chỉ định target; X0 chỉ giữ instruction, không có target. Tuy nhiên Nano/TX1 không hoàn toàn là lỗi do repo tự tạo: ngay §5 bài gốc định nghĩa TX1 nhưng prompt baseline §5.1 dùng Nano. Bám ví dụ gốc và có đối chứng nhân quả sạch là hai tiêu chí khác nhau. |
| SolarWinds chưa chứng minh T2 tốt hơn T1 | Đúng. 56 quan sát được chọn thích nghi theo chỉ báo biến thiên, không cân bằng. Nó vẫn cho phép mô tả từng trường hợp cụ thể; chưa đủ cho kết luận tổng quát hay tỷ lệ so sánh trực tiếp. |
| Chaining CVE thiếu prerequisite là vấn đề chính | Đúng về ngữ nghĩa. Giống tên quyền hay từ “execution” không chứng minh hai lỗ hổng nối được. Giả định fully connected của bài chỉ cho phép giao tiếp giữa các thành phần; không chứng minh cùng host/OS, credential dùng chung hoặc khả năng tiếp cận vật lý. |
| T0 là kết quả tích cực nhất | Hợp lý trong phạm vi worksheet. Tôi xác nhận 10/10 graph không rỗng; “20/20 nhánh đúng lõi” vẫn cần ghi là chấm sơ bộ, không phải mô phỏng khai thác thành công. |
| Merge chưa giải quyết completeness | Đúng. Hợp các node/edge chưa tự tạo quan hệ giữa các chunk. Nhưng §5.4 bài gốc là các thử nghiệm mở rộng, có cả continuation và zoom-in không đạt mục tiêu. Không cần tự giải quyết bài toán completeness mới được nói đã tái hiện các thao tác này. |
| 7/8 không nên gọi là recall 87,5% | Kết luận thận trọng phù hợp, nhưng lý do cần chính xác hơn: thiếu distractor không tự làm recall vô nghĩa nếu đã có nhãn relevance. Ở đây tám CVE là tập case study, chưa có nhãn liên quan độc lập cho query TX1, và record Jetson nói Nano/Nano 2GB. Vì vậy nên gọi “lấy được 7/8 CVE trong case study”; không coi tám record mặc nhiên là tám true positive. |
| Cần thêm distractor, baseline và chuyên gia | Có ích nếu nâng cấp thành đánh giá nghiên cứu; không bắt buộc để học hoặc demo pipeline. Người học vẫn nên tự kiểm tra vài cạnh và giữ nhãn sơ bộ trung thực. |

Một điểm nữa: graph có node cô lập hoặc thiếu một bridge giả định **không tự động là graph sai**. Nếu nguồn chưa chứng minh một quan hệ, không nối có thể hợp lý hơn nối cho đẹp. Năm stratum “thiếu cạnh/sự kiện” không phải năm lỗi đồng nhất; Jetson vắng khỏi C1 vì context không chứa nó.

Figure 7 của paper cũng minh họa những cạnh cần thận trọng, chẳng hạn liên hệ quyền quản trị với Glowworm. Việc tái hiện một hình không tự xác nhận tính hợp lệ của cạnh. Paper không cung cấp bộ nhãn chuẩn và thước đo accuracy toàn diện để dự án phải “đạt bằng”.

## 4. Hai vấn đề kỹ thuật đã xác nhận

### 4.1. Bộ tạo báo cáo có thể ghi đè kết luận đã sửa

Trong `scripts/run_paired_experiment.py`, hàm `write_reproduction_artifacts()`:

- Dòng 3280 gọi các response repair là “recovered by object extraction”.
- Dòng 3299–3300 còn ghi cứng rằng T0 Gemini rỗng ở cả năm repeat.
- Dòng 3355 ghi ra `REPRODUCTION_REPORT.md` ở gốc repo.

Đây là lỗi bảo trì có thật. Chạy lại đường sinh báo cáo có thể đưa kết luận cũ quay lại dù parser đã sửa. Lần kiểm tra này **chỉ tạo tài liệu học, chưa sửa code hoặc tái sinh báo cáo**. Trước khi chạy lại chức năng đó, cần bỏ kết luận ghi cứng, lấy kết quả từ metrics hiện hành và bảo vệ báo cáo đã biên tập khỏi ghi đè tự động. Đây là sửa cục bộ, không cần thêm kiến trúc hay tính năng mới.

### 4.2. “Raw-schema” là tên dễ gây hiểu sai

`response_graph_metrics()` đã lưu riêng `response_json_valid`, `extracted_graph_schema_valid`, `schema_valid` và `parser_repaired_truncation`. Tuy nhiên `schema_valid` vẫn có thể đúng khi parser đã repair; nó còn xét graph ở top level và thiếu khóa, nhưng không bắt buộc response gốc phải là JSON hợp lệ.

Khi trình bày, gọi đúng là **schema của graph trích xuất, có thể sau repair**, đồng thời báo riêng:

1. Response nguyên bản có phải JSON hợp lệ không?
2. Graph trích xuất có đạt schema không?
3. Parser đã repair hoặc nhà cung cấp báo chạm output cap không?
4. Nội dung và quan hệ tấn công có được nguồn hỗ trợ không?

Không nên chỉ đổi công thức `schema_valid` rồi áp nhãn mới cho số liệu lịch sử mà không tính lại và giải thích. Với mục tiêu học hiện tại, hiểu và diễn giải đúng các trường là đủ để đọc kết quả.

## 5. Khuyến nghị phạm vi tại thời điểm review 28/09

**Giữ:** hai đường vào CVE/report, extraction, SQLite, embedding, retrieval, prompt, response, parse, graph và các thí nghiệm đã lưu.

**Làm ngay:** học theo `HUONG_DAN_HOC_VA_DOC_CODE.md`; tự lần theo một CVE, đọc một graph T0 và kiểm tra vài quan hệ C1/C2 bằng nguồn. Dùng báo cáo gốc repo hiện hành cùng `offline_reevaluation`, không dùng kết luận lịch sử đã rút lại.

**Chỉ làm trước khi chạy lại runner:** sửa bộ tạo báo cáo ở mục 4. Không cần bước này để đọc code, chạy test hoặc thực hành offline theo hướng dẫn.

**Chưa cần cho việc bắt đầu học tại thời điểm review:** corpus lớn, distractor, thêm model, vector database, web UI, fine-tuning, engine tự chứng minh exploit chain, chấm lại 140 lượt SolarWinds hoặc gọi lại toàn bộ API. Kế hoạch hiện tại đã chọn thêm DeepSeek; phần học pipeline vẫn dùng được, còn phần thí nghiệm áp dụng thiết kế ba mô hình mới.

Mẫu kết luận cho số liệu run lịch sử hai mô hình:

> Dự án tái hiện quy trình CrystalBall theo bài báo, gồm truy hồi CVE, tạo prompt, sinh và hậu xử lý attack graph; đồng thời triển khai các nhóm thử nghiệm §5.1–5.4 bằng hai mô hình thay thế. Kết quả cho thấy pipeline vận hành được và có những graph giữ được các sự kiện, đường đi lõi trong case study. Đánh giá ngữ nghĩa còn sơ bộ; thiết kế hiện tại chưa chứng minh riêng lợi ích context, thứ hạng mô hình hoặc tính đầy đủ và khả thi của mọi attack path.

## 6. Nguồn để tự kiểm tra

- Bài báo local: `../../Using Retriever Augmented Large Language Models for Attack Graph Generation.pdf`, §3–5.4, trang in 2–8; Appendix A/B/C, trang 9–14.
- Báo cáo hiện hành: `../REPRODUCTION_REPORT.md`.
- Code: `../src/crystalball/`; điều phối và báo cáo: `../scripts/run_paired_experiment.py`.
- Dữ liệu nguồn: `../data/cve_official/manifest.json`, `../data/reproduction/manifest.json`.
- Bằng chứng local: `../outputs/experiments/20260927_full_reproduction/`.
- Metrics và worksheet được sửa: thư mục `offline_reevaluation/` bên trong run trên.

Các đường dẫn bằng chứng lịch sử có trên máy này, không mặc nhiên có trong bản clone GitHub. Không cần xuất bản toàn bộ artifact để bắt đầu học local.

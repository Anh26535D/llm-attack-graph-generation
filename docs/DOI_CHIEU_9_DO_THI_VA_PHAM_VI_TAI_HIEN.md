# Đối chiếu chín attack graph và phạm vi tái hiện

Ngày đối chiếu: 12/10/2026. Đã đọc PDF gốc 14 trang, PDF báo cáo của nhóm 10 trang, code hiện tại và artifact local của run `20260927_full_reproduction`.

Cập nhật phạm vi ngày 13/10/2026: nhóm chọn **Gemini, GPT-5.6 Luna và DeepSeek** làm ba mô hình độc lập cho phần tái hiện. Xem [thiết kế thí nghiệm ba mô hình](THI_NGHIEM_BA_MO_HINH.md). Số liệu và gallery dưới đây vẫn thuộc run hai mô hình đã lưu.

## 1. Kết luận cho bài tập môn học

**Có thể tái hiện toàn bộ các loại đầu vào và cách sinh graph minh họa trong bài gốc bằng code hiện tại.** Repo có đủ pipeline extraction → embedding → retrieval → prompt → LLM → parse → visualization, cùng các thử nghiệm mở rộng §5.4. Các điều kiện đã chạy bằng hai model thay thế và có raw response lưu trên máy.

Tuy nhiên, đây là tái hiện phương pháp và kịch bản. Chưa phải tái tạo nguyên trạng chín hình bằng đúng GPT-4, GPT-3.5, Bard của bài gốc; cũng không bảo đảm giống từng node, cạnh hay vị trí. Muốn lặp đúng model lịch sử phải kiểm tra quyền truy cập đúng phiên bản, cùng cấu hình và dữ liệu gốc. PDF cung cấp prompt và hình minh họa, nhưng không đủ để đảm bảo khôi phục chính xác một lần sinh ngẫu nhiên của tác giả.

Mục tiêu hiện tại là dùng ba mô hình thay thế để có phần so sánh giống cách tổ chức của bài gốc. DeepSeek đã được bổ sung vào client và demo; cần mở rộng runner và tổng hợp kết quả để thực hiện bộ thí nghiệm ba mô hình. Không cần viết lại thuật toán sinh graph hoặc thêm prompt nguồn cho năm kịch bản đã có.

## 2. Chín graph không phải chín thuật toán hay chín prompt độc lập

Bài gốc có 13 hình. Trong đó chín attack graph là **Figure 2, 6, 7, 8, 9, 10, 11, 12, 13**. Figure 1 là mô tả CVE; Figure 3, 4, 5 là sơ đồ hệ thống/quy trình.

| Hình gốc | Model được ghi trong bài | Đầu vào / prompt | Điều kiện tương ứng trong repo | Tình trạng hiện tại |
|---|---|---|---|---|
| 2 | GPT-4 | SolarWinds đầy đủ, Appendix C.1 | T1 | Có prompt nguồn và 5 response/model cho hai model thay thế |
| 6 | ChatGPT | Prompt không CVE context ở §5.1 | C0 | Có prompt và 5 response/model |
| 7 | GPT-4 | Đủ tám mô tả CVE, Appendix A | C2 | Có prompt và 5 response/model |
| 8 | GPT-4 | SolarWinds evasion, Appendix C.2 | T2 | Có prompt và 5 response/model |
| 9 | GPT-3.5 | Cùng Appendix A như Figure 7 | C2 | Có kết quả so sánh hai model thay thế |
| 10 | Bard | Cùng Appendix A như Figure 7 | C2 | Đã chọn DeepSeek làm model thứ ba; chưa có response C2 |
| 11 | GPT-4 | Hai nhánh PostgreSQL/container, Appendix B | T0 | Có prompt và 5 response/model; dùng parser đã sửa |
| 12 | GPT-3.5 | Cùng Appendix B như Figure 11 | T0 | Có kết quả so sánh hai model thay thế |
| 13 | Bard | Cùng Appendix B như Figure 11 | T0 | DeepSeek đã có demo `--report`; chưa có response T0 |

Các row so sánh model không tự tương đương một model lịch sử cụ thể. Ví dụ, output Gemini của nhóm không được ghi là output GPT-4. Bảng trên chỉ ánh xạ **kịch bản/prompt**.

Như vậy, chín graph được tạo từ **năm kịch bản**: C0, C2, T0, T1, T2. Figure 7/9/10 dùng một prompt ở ba model; Figure 11/12/13 cũng vậy.

**C1 khác C2:** C1 là context do Contriever thực sự truy hồi, hiện gồm 7 CVE. C2 giữ đủ tám description của Appendix A để đối chiếu nhóm Figure 7/9/10. `demo_online.py --cve` minh họa C1; không nên gọi đó là chạy nguyên prompt Appendix A.

## 3. Tài nguyên đã có

- `data/cve_official/`: tám record CVE chính thức, manifest nguồn/hash.
- `data/reproduction/appendix_a_context.txt`: prompt C2.
- `data/reproduction/kubernetes_appendix_b.txt`: prompt T0.
- `data/reproduction/solarwinds_full_appendix_c1.txt`: prompt T1.
- `data/reproduction/solarwinds_evasion_appendix_c2.txt`: prompt T2.
- Prompt C0 nằm trong `build_conditions()` và bản freeze của run.
- `data/db/official_cve_3ece5b6bc3739cff.sqlite3`, vector và index manifest: có sẵn local.
- `outputs/experiments/20260927_full_reproduction/`: 130 raw response; 70 request điều kiện chính và 60 request mở rộng §5.4.
- Năm kịch bản tương ứng các hình × hai model × năm repeat = **50 response chính liên quan trực tiếp tới chín graph**. C1 và X0 bổ sung 20 request; §5.4 bổ sung 60.
- Hai model trong metadata: Gemini `gemini-3.8-flash`, OpenRouter `openai/gpt-5.6-luna`.
- Mô hình thứ ba đã cấu hình: DeepSeek `deepseek/deepseek-v4.1-flash`, backend `openrouter_v2`, provider chọn bằng `OPENROUTER_PROVIDER_CONFIG_V2`. Hậu tố `_V2` chỉ phân biệt cấu hình OpenRouter thứ hai; chưa có dữ liệu thí nghiệm DeepSeek.
- Các thao tác chunk/merge, cutoff/continuation, edge detail và edge context đã được triển khai và chạy. Chúng không có thêm hình đánh số riêng trong bài gốc.

Đã kiểm tra SHA-256 của PDF gốc và bốn file Appendix khớp manifest hiện có. Việc khớp hash xác nhận tính nhất quán với bộ nguồn local, không phải một lần xác thực nguồn trực tuyến mới.

## 4. Đã bổ sung bộ demo offline

Script mới `scripts/export_paper_demo.py` đọc raw response cùng metrics đã sửa, kiểm tra hash và parse lại bằng code hiện tại. Nó không khởi tạo client LLM và không gửi API. Đầu ra nằm trong thư mục mới; không ghi đè run lịch sử.

```powershell
Set-Location "D:\AHUST\An ninh mạng\llm-attack-graph-generation"
uv run --no-sync python scripts/export_paper_demo.py --include-rag
```

Lệnh mặc định xuất năm kịch bản × hai model = 10 graph. `--include-rag` thêm hai output C1, tổng 12. Đây là gallery của **run lịch sử hai mô hình**, chưa có cột DeepSeek; exporter cần mở rộng để đọc bộ ba mô hình sau này. Có thể chọn `--repeat 2` đến `--repeat 5`; phải ghi rõ repeat đã chọn. Không lựa chọn graph lớn/đẹp/đúng nhất rồi dùng nó thay thống kê năm repeat.

Bộ đã xuất trong lần đối chiếu này:

```text
outputs/paper_demo/20261012T160411254414Z/index.html
```

Mỗi thư mục con chứa `graph.png`, `graph.svg`, `graph.html`, `graph.json`, `prompt.txt`, `response.txt`, `metadata.json`. Gallery ghi model thật, số node/edge, repeat và cảnh báo. Mở bằng:

```powershell
Invoke-Item "outputs/paper_demo/20261012T160411254414Z/index.html"
```

### Số lượng trong bộ minh họa repeat 1

| Điều kiện | Gemini: node/edge | Luna: node/edge |
|---|---:|---:|
| C0 | 8 / 7 | 15 / 24 |
| C1 — bổ sung RAG | 8 / 6 | 13 / 8 |
| C2 | 8 / 5 | 13 / 13 |
| T0 | 10 / 10 | 17 / 20 |
| T1 | 25 / 27 | 115 / 111 |
| T2 | 19 / 20 | 55 / 64 |

Luna T1 repeat 1 bị chạm output cap, JSON đã repair; phải giữ nhãn **graph có thể thiếu**. C0/T0 không đạt schema đầy đủ của repo vì yêu cầu prompt khác; không suy ra graph rỗng. Đây là ví dụ của một repeat, không phải số trung bình trong báo cáo.

Kiểm tra kỹ thuật: count và hash của 12 đầu vào khớp bằng chứng đã lưu; parser và renderer tạo đủ output. Ba test renderer hiện tại đã qua. PNG đã được xem ở C2, T0, T1 Gemini; các graph đông node/nhãn nên dùng HTML hoặc phóng to SVG để đọc chi tiết. Xuất hình không chấm lại ngữ nghĩa các quan hệ.

## 5. Những điểm phải phân biệt khi lấy hình

### Hình và graph T0 cũ

Một số artifact ở `graphs/<backend>/T0/` gốc run còn thể hiện kết quả của parser cũ, khi wrapper `attack_graph` chưa được xử lý đúng. Raw response không rỗng. Bản đúng nằm trong `offline_reevaluation/graphs/`; exporter mới parse trực tiếp raw và kiểm tra against corrected metrics.

Không dùng các PNG/JSON T0 cũ để nói model trả graph rỗng. Trong repeat 1 đã kiểm tra, Gemini có 10 node/10 edge và Luna có 17 node/20 edge.

### Demo chi tiết khác prompt bài báo

`demo_online.py` mặc định bổ sung instruction bám nguồn, category và source_refs, output cap 16.384 token, reasoning medium cho Gemini/Luna, high cố định cho DeepSeek. Để demo SolarWinds theo prompt bài gốc:

```powershell
uv run --no-sync python scripts/demo_online.py --paper-prompt
uv run --no-sync python scripts/demo_online.py --evasion --paper-prompt
uv run --no-sync python scripts/demo_online.py --report
```

Thêm `--backend gemini`, `--backend openrouter` hoặc `--backend openrouter_v2` để chọn từng mô hình; thêm `--reasoning high` để yêu cầu high cho cả ba khi tạo demo so sánh mới. `--report` cùng ba backend minh họa T0, một trong hai nhóm so sánh ba mô hình của bài gốc.

Đây là request mới có thể tính phí. Không gọi demo chi tiết mặc định là lặp nguyên cấu hình thí nghiệm đã báo cáo. Replay nguồn gốc cũng phải chọn đúng mode/prompt. Bộ exporter mới giữ nguyên prompt, cap warning và model của request lịch sử, thuận tiện hơn khi đối chiếu nhiều hình.

### Runner có báo cáo ghi cứng cần sửa trước đợt mới

`write_reproduction_artifacts()` trong `scripts/run_paired_experiment.py` còn chuỗi kết luận cũ rằng T0 Gemini rỗng và còn ghi ra `REPRODUCTION_REPORT.md` ở gốc repo. Đường sinh báo cáo có thể đưa kết luận đã rút lại quay lại. Exporter mới không gọi hàm này.

Trước khi chạy lại full runner, cần lấy kết luận từ metrics hiện hành, bỏ nhận xét cũ ghi cứng và bảo vệ báo cáo đã biên tập khỏi ghi đè. Lần này chưa sửa runner hoặc thực hiện đợt API mới.

## 6. Cần thêm code hay prompt?

| Mục tiêu | Việc cần thêm |
|---|---|
| Đọc và trình bày run lịch sử hai model | Không cần thêm prompt hoặc gọi lại API; dùng bộ exporter/gallery hiện có |
| Demo RAG vận hành | Chạy C1 `--cve --check` để show retrieval; dùng gallery C1 hoặc gọi một request mới khi cần |
| Một nút/lệnh chạy mới cho từng C0/C2/T0/T1/T2 | Thêm lựa chọn scenario hoặc script runner nhỏ; dùng lại prompt hiện có |
| Demo cùng T0 trên ba model | Client đã hỗ trợ; chạy `--report` lần lượt với `gemini`, `openrouter`, `openrouter_v2`; mỗi lần một request |
| Thí nghiệm ba model như nhóm hình gốc | Đã chọn DeepSeek; cần mở rộng runner và exporter, giữ prompt C2/T0 giống nhau, năm repeat và lưu kết quả riêng |
| Tái hiện đúng GPT-4/GPT-3.5/Bard lịch sử | Cần model/version gốc có quyền truy cập và cấu hình gốc; không thể đảm bảo chỉ bằng thay prompt |
| Thêm một case study khác | Cần dữ liệu/context và prompt mới; không phải yêu cầu để bao phủ chín hình hiện có |
| Chứng minh tác dụng riêng của RAG hoặc đúng mọi path | Thiết kế đối chứng/ground truth và đánh giá mới, ngoài yêu cầu minh họa năm kịch bản |

Full runner hiện khóa hai model trong `MODEL_SPECS` và kiểm tra đúng hai model ID. Vì vậy, chỉ sửa `.env` không đủ để mở rộng full runner thành ba model. Cần bổ sung DeepSeek vào danh sách client, kế hoạch request, ID kết quả và báo cáo; dùng lại các prompt đã có. Chi tiết trạng thái và phần cần sửa nằm trong [tài liệu ba mô hình](THI_NGHIEM_BA_MO_HINH.md).

Mục tiêu đợt mới là **năm kịch bản × ba model × năm repeat = 75 response generation**. Nếu chỉ bổ sung DeepSeek vào dữ liệu cũ, năm kịch bản cần 25 response, hoặc riêng C2/T0 cần 10; không cần xây lại index vì prompt/context đã có. Tuy nhiên run cũ dùng reasoning low, DeepSeek hiện high: phải ghi rõ khác biệt cấu hình nếu dùng lại dữ liệu, không coi đó là phép so sánh chỉ thay model. Chỉ minh họa một repeat C2/T0 cần hai request, chưa đủ cho thống kê năm repeat. Thêm model là thí nghiệm mới, phải ghi run và phạm vi đánh giá riêng.

## 7. Bổ sung gì cho PDF của nhóm?

PDF của nhóm đã có Mục VII về tái hiện: dữ liệu, thiết kế, số liệu và giới hạn. Các Hình 2, 6–13 hiện được chú thích **nguồn: [1]**, là hình dùng để trình bày bài gốc. Chúng chưa minh họa trực tiếp output mà code của nhóm tạo ra.

Nên giữ vai trò của các hình gốc trong phần khảo sát, rồi bổ sung hình của nhóm vào Mục VII hoặc phụ lục:

1. C0 và C2 của cùng một model, để thấy khác biệt đầu ra của hai prompt. Ghi rõ hai prompt không chỉ khác context, nên đây chưa phải đối chứng nhân quả sạch.
2. C2 và T0 của Gemini, Luna và DeepSeek ở cùng repeat sau khi chạy bộ mới, để minh họa so sánh model. Hiện chỉ có kết quả Gemini/Luna; ghi DeepSeek chưa chạy, không tự điền số liệu. Không xếp hạng chỉ từ số node/edge.
3. T1 và T2 của cùng một model, để minh họa full report và excerpt. Không suy ra excerpt luôn tốt hơn từ một cặp hình.
4. Một ví dụ kiểm tra cạnh bằng nguồn và điều kiện khai thác, cho thấy nhóm hiểu giới hạn của graph.

Chú thích gợi ý:

> Hình X. Đồ thị T0 do nhóm tái hiện từ prompt Appendix B bằng Gemini `gemini-3.8-flash`, run `20260927_full_reproduction`, repeat 1. Graph có 10 nút và 10 cạnh; hình được vẽ lại từ raw response bằng parser hiện tại. Kết quả minh họa quy trình, không xác nhận mọi quan hệ khai thác trên hệ thống thực.

Ở thời điểm hiện tại, ghi: **“Dự án đã hỗ trợ demo bằng ba mô hình thay thế Gemini, GPT-5.6 Luna và DeepSeek; kết quả định lượng hiện có thuộc run hai mô hình. Bộ thí nghiệm ba mô hình đang được chuẩn bị.”** Sau khi chạy và đánh giá đủ, cập nhật kết luận theo số liệu thực tế. Không ghi đã khôi phục chính xác chín hình hoặc dùng đúng ba model lịch sử của bài gốc.

Nếu giới thiệu T0, gọi rõ đây là hai nhánh PostgreSQL/container trong Appendix B, được bài gốc đặt trong case study Kubernetes. Dữ liệu này chưa chứng minh đã demo một cụm Kubernetes thực hoặc cơ chế Kubernetes đặc thù.

## 8. Phạm vi demo đề xuất

1. Show hai sơ đồ pipeline và mapping Figure → scenario.
2. Chạy `--cve --check` để show query, 7 CVE được truy hồi và prompt.
3. Mở gallery offline của run cũ để so C0/C2 và T0; sau khi có output mới, trình bày T0 ba cột Gemini/Luna/DeepSeek, ghi rõ các run và cấu hình.
4. Chọn một cạnh, đọc JSON và nguồn; nêu prerequisite còn cần xác nhận.
5. Nếu muốn show generation trực tiếp, gọi một demo SolarWinds/Appendix B với backend đã chọn rồi dùng các output chuẩn bị trước làm phương án dự phòng.

Phạm vi này dùng tài nguyên hiện có để trình bày pipeline. Muốn hoàn tất mục tiêu thí nghiệm ba mô hình, cần bổ sung runner, chạy và đánh giá bộ đã chốt; không cần thêm corpus hoặc prompt chỉ để bao phủ chín hình.

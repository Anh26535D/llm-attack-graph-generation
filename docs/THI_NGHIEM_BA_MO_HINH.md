# Runner chín hình và demo online với ba mô hình

Cập nhật 13/10/2026. Ưu tiên chín attack graph trong bài báo, không chạy full C1/X0/§5.4. Gemini, GPT-5.6 Luna và DeepSeek là mô hình thay thế GPT-4/GPT-3.5/Bard, không phải cùng phiên bản của tác giả.

## 1. Ánh xạ các hình

| Figure | Kịch bản/prompt | Backend/model mặc định |
|---|---|---|
| 2 | T1 — toàn SolarWinds Appendix C.1 | `gemini` — Gemini |
| 6 | C0 — không CVE context | `gemini` — Gemini |
| 7 | C2 — đủ tám CVE Appendix A | `gemini` — Gemini |
| 8 | T2 — SolarWinds evasion Appendix C.2 | `gemini` — Gemini |
| 9 | C2 — cùng prompt Figure 7 | `openrouter` — GPT-5.6 Luna |
| 10 | C2 — cùng prompt Figure 7 | `openrouter_v2` — DeepSeek |
| 11 | T0 — PostgreSQL/container Appendix B | `gemini` — Gemini |
| 12 | T0 — cùng prompt Figure 11 | `openrouter` — GPT-5.6 Luna |
| 13 | T0 — cùng prompt Figure 11 | `openrouter_v2` — DeepSeek |

Chín hình dùng năm kịch bản; C2/T0 so trên ba model giống cách tổ chức hai nhóm hình của paper. Mặc định **9 request, một repeat**. `--repeat 5` là **45 request** theo ánh xạ này, không phải 75 request của thiết kế chạy mọi kịch bản trên mọi model.

## 2. Cấu hình và cài đặt

Trên máy mới, cài `uv`, clone repo, mở terminal tại thư mục repo và sao chép `.env.example` thành `.env`. Để vẽ lại từ kết quả đã commit không cần API key. Để sinh mới đủ chín hình, điền `GEMINI_API_KEY`, `OPENROUTER_API_KEY` và `OPENROUTER_API_KEY_V2`; model ID/provider đã có trong mẫu. DeepSeek dùng:

```dotenv
OPENROUTER_API_KEY_V2=YOUR_API_KEY
OPENROUTER_MODEL_V2=deepseek/deepseek-v4.1-flash
OPENROUTER_PROVIDER_CONFIG_V2='{"only":["baidu/fp8"],"allow_fallbacks":false}'
```

`_V2` chỉ là profile OpenRouter thứ hai. Đổi provider bằng `only`. Runner dùng reasoning `high` cho cả ba, cap mặc định 16.384 token; không cần thêm config môi trường. Cùng tên reasoning không bảo đảm ba API có cùng lượng tính toán.

```powershell
uv sync --locked --inexact --extra dev --extra gemini --extra openrouter --extra paper
```

Extra `paper` cài pypdf để tách ảnh gốc từ PDF đã pin trong manifest nếu có PDF. Nếu clone không có PDF, runner dùng ảnh tham chiếu trong `outputs/paper_nine/paper9_20261013_original/references/`, kiểm tra hash nguồn PDF và từng PNG trước khi sao chép. Không cần tải lại PDF, index hoặc Contriever cho năm prompt nguồn này.

Vẽ lại bộ đã lưu và hai sơ đồ quy trình trên máy mới, không gọi API:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
.\paper_demo.bat --resume outputs/paper_nine/paper9_20261013_reviewed --render-only
.\presentation_demo.bat
```

`presentation_demo.bat` dùng `scripts/generate_presentation_diagrams.py`, xuất hai cặp PNG/SVG vào `outputs/demo_presentation/`. Có thể chọn thư mục khác bằng `--output-dir PATH`.

## 3. Chạy đúng chín hình

```powershell
.\paper_demo.bat --check --no-open
.\paper_demo.bat
```

Hoặc sau khi sync:

```powershell
uv run --no-sync python scripts/run_paper_experiment.py --run-id paper9_demo --check --no-open
uv run --no-sync python scripts/run_paper_experiment.py --resume outputs/paper_nine/paper9_demo
```

`--check` chuẩn bị chín prompt/cấu hình và ảnh nguồn, không gọi LLM. Lệnh sau gửi một request cho mỗi hình chưa có response, lưu ngay sau từng request. Không ghi đè run 130 response hoặc báo cáo tổng hợp ở gốc repo.

`--prompt-style paper` mặc định giữ nguyên prompt nguồn. `--prompt-style presentation` thêm schema nhãn ngắn, đầy đủ và hướng dẫn graph ở mức tổng quan; đây là biến thể trình bày, ghi riêng khi báo cáo. Không đổi variant giữa chừng trong cùng run.

## 4. Demo online đủ chín trường hợp

```powershell
.\demo_online.bat --figure 2
.\demo_online.bat --figure 6
.\demo_online.bat --figure 7
.\demo_online.bat --figure 8
.\demo_online.bat --figure 9
.\demo_online.bat --figure 10
.\demo_online.bat --figure 11
.\demo_online.bat --figure 12
.\demo_online.bat --figure 13
```

Mỗi lệnh tự chọn backend theo bảng, gọi một request và mở gallery. Có thể override bằng `--backend gemini`, `openrouter`, `openrouter_v2`. `--nine` chạy toàn bộ; thêm `--check --no-open` để kiểm tra trước buổi trình bày.

“Online” là gọi API sinh JSON mới; HTML hiển thị vẫn hoạt động offline sau khi có response. Nên chuẩn bị đủ chín ảnh trước, demo trực tiếp một hình rồi mở gallery.

## 5. Tách ảnh để so sánh và chỉnh bố cục

```text
outputs/paper_nine/<run>/
  manifest.json, index.html
  references/figure_02.png ... figure_13.png
  figures/figure_02_r01/
    prompt.txt, response.txt, metadata.json
    graph.json, graph.png, graph.svg, graph.html
    render.json, comparison.html
  ... các hình còn lại
```

Mỗi `comparison.html` đặt đúng ảnh gốc và ảnh tái hiện cạnh nhau. Ảnh dùng nút tròn, tên nút bên ngoài và tên quan hệ trên cạnh; không thay bằng N1/E1. Nếu label có dạng “tên: chi tiết”, ảnh hiện phần tên; toàn bộ label/chi tiết vẫn có trong JSON và panel tương tác. `render.json` lưu cả tên hiển thị và label nguyên bản.

Trong C2 khi nhận diện được đủ tám CVE, ảnh dùng tên lỗ hổng và tên chuyển tiếp ngắn để đọc như bài báo; label/điều kiện nguyên bản của LLM vẫn giữ trong JSON/HTML và `original_node_labels`/`original_edge_labels`. Đây là chuẩn hóa tên hiển thị, không xác nhận rằng các chuỗi CVE khả thi.

Figure 13 có thêm `overview/`: bản gom nhóm biên tập gồm bốn nút/hai cạnh để đối chiếu với ảnh Bard ít chi tiết. Graph mô hình đầy đủ vẫn ở `graph.json/png/svg/html`. `overview/mapping.json` liệt kê node gốc của từng nhóm, cạnh gốc của từng quan hệ và nút ngữ cảnh bị bỏ khỏi ảnh rút gọn; không suy diễn cạnh mới. Gallery ghi rõ ảnh rút gọn, không dùng số 4/2 làm số liệu output DeepSeek.

Renderer không thêm/xóa node hoặc edge để ép giống paper. Nó đổi seed/bố cục và giãn khoảng cách để giảm chồng nhãn, ghi số nhãn còn chồng. Có thể vẽ lại từ cùng response, không gọi API:

```powershell
uv run --no-sync python scripts/run_paper_experiment.py --resume outputs/paper_nine/RUN_ID --render-only --layout-seed 17
```

So từng cặp về số node/edge, các cụm/nhánh, mức độ tổng quan, tên kỹ thuật, hướng và tên quan hệ, nhãn bị chồng hoặc cắt. Mô hình mới có thể phân rã khác Bard/GPT lịch sử; ghi khác biệt thay vì sửa dữ liệu cho giống hình. Giống bố cục chưa chứng minh đúng ngữ nghĩa.

`--resume` tái sử dụng response đã có. Lỗi API không gửi lại tự động; đọc metadata trước khi dùng `--retry-failed`. Đổi model/prompt thì tạo run mới. `--import-history PATH` chỉ nhập response khớp prompt và hash; ghi rõ run cũ reasoning low, không coi đó là so sánh đồng cấu hình với high mới.

## 6. Báo cáo và slide

Đưa bảng ánh xạ, sơ đồ pipeline, chín ảnh của nhóm và các cặp so sánh vào phần tái hiện. Ghi model ID thật, Figure/kịch bản, run, repeat, prompt variant, reasoning/cap và cảnh báo repair. Hình gốc giữ chú thích nguồn [1].

So ba model ở C2/T0, dùng mô hình chính cho C0/T1/T2. Một repeat đủ minh họa demo, chưa đủ để xếp hạng thống kê. Đếm node/edge đo độ lớn, còn quan hệ tấn công phải được đối chiếu với nguồn.

[Báo cáo lịch sử](../REPRODUCTION_REPORT.md) vẫn tổng hợp hai mô hình của run 130 response. E1/H1 là thí nghiệm phụ. Runner đầy đủ §5.1–5.4 cũ chưa mở rộng sang DeepSeek; runner chín hình đáp ứng phạm vi ưu tiên hiện tại.

## 7. Bộ ảnh đã chạy trên máy này

- `outputs/paper_nine/paper9_20261013_original/`: đủ chín response mới với prompt nguyên bản, reasoning high.
- `outputs/archive/20261013_cleanup/paper_nine/paper9_20261013_presentation/`: đủ chín response của biến thể tổng quan; Figure 2 tái dùng response từ thử nghiệm riêng có cùng prompt/hash/model/cap.
- `outputs/paper_nine/paper9_20261013_reviewed/`: bộ chín ảnh được chọn để trình bày. Figure 2/6 dùng variant tổng quan; các hình còn lại dùng original. Cả ba model của C2 và cả ba model của T0 vẫn nhận cùng prompt trong từng nhóm. `selected_from` ghi nguồn từng ảnh.

Sau khi dọn output ngày 13/10, bản presentation và thử Figure 2 riêng nằm trong `outputs/archive/20261013_cleanup/paper_nine/`. Metadata lịch sử giữ nguyên; `source_locations.json` trong reviewed ghi đường dẫn nguồn hiện tại. Run mới `outputs/paper_nine/20261013T142243458365Z/` đã có đủ chín response và được giữ để đối chiếu, chưa thay bộ reviewed. Xem [hướng dẫn giữ/archive output](../outputs/README.md).

Bộ `reviewed` là tuyển chọn minh họa sau khi xem ảnh, không phải mẫu ngẫu nhiên để xếp hạng model. Mở `index.html` và từng `comparison.html`, dùng PNG/SVG hoặc overview đã ghi nhãn cho báo cáo/slide. Tổng cộng đợt làm này gửi 18 request generation: chín original, một Figure 2 tổng quan thử riêng, tám request bổ sung cho bộ presentation. Các lần chỉnh ảnh sau đó chỉ render lại response.

[Mở bộ chín ảnh đã kiểm tra](../outputs/paper_nine/paper9_20261013_reviewed/index.html) · [Bảng kiểm tra và số node/edge](../outputs/paper_nine/paper9_20261013_reviewed/quality_review.md). Bộ reviewed, original và run mới đã được lưu trong Git; các bản thử/archive vẫn local. Tất cả chín response trong bộ reviewed kết thúc STOP, không repair JSON; renderer ghi không còn chồng nhãn. T0 có cảnh báo khác schema đầy đủ của repo vì prompt Appendix B dùng schema riêng; graph vẫn có đủ node/edge đã parse.

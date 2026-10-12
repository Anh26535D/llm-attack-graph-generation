# Quy trình chạy, demo và trình bày CrystalBall

Đối chiếu với code và kiểm tra offline ngày 12/10/2026; cập nhật phạm vi ba mô hình ngày 13/10/2026. Các lệnh dưới đây dùng PowerShell.

Phạm vi hiện tại dùng **Gemini, GPT-5.6 Luna và DeepSeek** làm ba mô hình thay thế cho phần tái hiện. Demo đã hỗ trợ chọn cả ba; batch runner/gallery còn dùng hai mô hình của run lịch sử. Xem [thí nghiệm ba mô hình](THI_NGHIEM_BA_MO_HINH.md) để biết cấu hình, kế hoạch và phần code còn thiếu. DeepSeek là mô hình bổ sung; tên kỹ thuật `openrouter_v2` không phải phiên bản của dự án.

## 1. Lệnh chạy dự án hiện tại

Từ thư mục đang mở trong Codex:

```powershell
Set-Location "D:\AHUST\An ninh mạng\llm-attack-graph-generation"
.\demo_online.bat
```

Đây là dự án Python chạy bằng script CLI. Lệnh trên đọc báo cáo SolarWinds/SUNBURST, tạo prompt, gọi **một request LLM** rồi xuất attack graph. Kết thúc sẽ mở `graph.html` trong trình duyệt. Một lần gọi API mới có thể tính phí và phụ thuộc quyền truy cập model của tài khoản.

BAT đồng bộ thư viện mỗi lần chạy. Nếu môi trường đã cài đủ thư viện, có thể chạy trực tiếp:

```powershell
uv run --no-sync python scripts/demo_online.py
```

### Chuẩn bị trên máy mới

```powershell
uv sync --locked --extra dev --extra embeddings --extra gemini --extra openrouter
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

Sửa `.env`, chọn một backend và điền API key cùng model tài khoản được phép gọi:

```dotenv
LLM_BACKEND=gemini
GEMINI_API_KEY=YOUR_API_KEY
GEMINI_MODEL=YOUR_AVAILABLE_MODEL_ID
```

Ba mô hình được chọn độc lập bằng `--backend`:

| Mô hình | Backend | Cấu hình key/model |
|---|---|---|
| Gemini `gemini-3.8-flash` | `gemini` | `GEMINI_API_KEY`, `GEMINI_MODEL` |
| GPT-5.6 Luna `openai/gpt-5.6-luna` | `openrouter` | `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` |
| DeepSeek `deepseek/deepseek-v4.1-flash` | `openrouter_v2` | `OPENROUTER_API_KEY_V2`, `OPENROUTER_MODEL_V2`, `OPENROUTER_PROVIDER_CONFIG_V2` |

Cấu hình DeepSeek:

```dotenv
OPENROUTER_API_KEY_V2=YOUR_API_KEY
OPENROUTER_MODEL_V2=deepseek/deepseek-v4.1-flash
OPENROUTER_PROVIDER_CONFIG_V2='{"only":["baidu/fp8"],"allow_fallbacks":false}'
```

Muốn đổi provider, sửa slug trong `only`. DeepSeek dùng reasoning `high` cố định trong code, không cần thêm biến môi trường. Không thay các placeholder vào `.env` đang hoạt động. Máy hiện tại đã có `uv`, `.venv`, `.env` và index CVE chính thức. Kiểm tra offline chỉ xác nhận đọc cấu hình/tạo prompt, chưa xác nhận quyền truy cập model hoặc quota ở máy chủ.

## 2. Chọn đúng kịch bản

| Mục đích | Lệnh sau khi vào thư mục repo | Đặc điểm |
|---|---|---|
| SolarWinds đầy đủ | `.\demo_online.bat` | Báo cáo → prompt chi tiết → LLM; không truy hồi CVE |
| Thể hiện CVE RAG | `.\demo_online.bat --cve` | Tên sản phẩm → Contriever → CVE context → LLM |
| Báo cáo Appendix B | `.\demo_online.bat --report` | Dùng nguyên prompt Appendix B đã có trong file |
| Tập trung né tránh | `.\demo_online.bat --evasion` | Dùng nguồn SolarWinds evasion Appendix C.2 |
| Giữ prompt SolarWinds nguyên bản | `.\demo_online.bat --paper-prompt` | Không dùng instruction bổ sung của demo chi tiết |
| Chọn Gemini cho một lần | `.\demo_online.bat --backend gemini` | Mô hình thứ nhất |
| Chọn Luna cho một lần | `.\demo_online.bat --backend openrouter` | Mô hình thứ hai, qua OpenRouter |
| Chọn DeepSeek cho một lần | `.\demo_online.bat --backend openrouter_v2` | Mô hình thứ ba, dùng provider đã chọn trong `.env` |
| Chỉ chuẩn bị prompt | `.\demo_online.bat --check --no-open` | Không gửi request LLM; vẫn cần cấu hình client hợp lệ |

Các tùy chọn tương tự dùng được với `uv run --no-sync python scripts/demo_online.py`. Mặc định demo chi tiết dùng output cap 16.384 token, reasoning medium cho Gemini/Luna và high cho DeepSeek. Đây là biến thể demo bổ sung yêu cầu bám nguồn, khác cấu hình thí nghiệm lịch sử và prompt nguyên bản.

### Cùng một đầu vào qua ba mô hình

Dùng T0 Appendix B để demo so sánh đơn giản, không cần index CVE:

```powershell
uv run --no-sync python scripts/demo_online.py --backend gemini --report --reasoning high
uv run --no-sync python scripts/demo_online.py --backend openrouter --report --reasoning high
uv run --no-sync python scripts/demo_online.py --backend openrouter_v2 --report --reasoning high
```

Mỗi lệnh gọi một request mới và mở graph của mô hình tương ứng. Thêm `--check --no-open` để kiểm tra cả ba trước buổi trình bày mà không gửi request. Ba output này là **một repeat demo**; bộ thí nghiệm dự kiến dùng cùng năm kịch bản và năm repeat, cần mở rộng runner trước khi chạy batch. `--cve` minh họa C1, không thay cho prompt C2 Appendix A của nhóm Figure 7/9/10.

## 3. Quy trình demo 5–7 phút

### Trước buổi trình bày

1. Cài dependency và chuẩn bị API key từ trước. Tránh chờ tải thư viện khi đang trình bày.
2. Chạy preflight SolarWinds:

   ```powershell
   uv run --no-sync python scripts/demo_online.py --check --no-open
   ```

   Mở `prompt.txt` trong thư mục output vừa in. Chế độ này kiểm tra việc đọc nguồn và tạo prompt; không xác nhận quota hoặc xác thực API ở máy chủ.
3. Nếu giới thiệu RAG, kiểm tra riêng nhánh CVE:

   ```powershell
   uv run --no-sync python scripts/demo_online.py --cve --check --no-open
   ```

   Cần index Contriever đã sẵn sàng. Máy này đã kiểm tra thành công với 7 CVE được đưa vào context. Trên máy clone mới, index/vector không có trong Git; xem README mục 6 để dựng index. Đừng chạy lại extraction trong buổi demo khi index đã có.
4. Khi trình bày so sánh ba mô hình, tạo trước ba output cùng T0/prompt/cap, ghi lại ba đường dẫn run. Chuẩn bị output đã hoàn tất để phát lại nếu API chậm hoặc hết quota; trong buổi demo chỉ cần gọi trực tiếp một mô hình rồi mở hai kết quả còn lại.

### Trong buổi trình bày

| Thời lượng dự kiến | Thao tác | Ý cần nói |
|---|---|---|
| 30–45 giây | Giới thiệu đầu vào và đầu ra | Hệ thống hỗ trợ chuyển thông tin lỗ hổng/báo cáo thành đồ thị có hướng |
| 45–60 giây | Mở file nguồn và `prompt.txt` | Dữ liệu nguồn cung cấp bằng chứng; prompt quy định cấu trúc node/edge |
| 1–2 phút, tùy API | Chạy một demo T0/SolarWinds hoặc `--cve` | Nêu mô hình đang gọi; báo cáo đi trực tiếp vào prompt, CVE RAG có retrieval riêng |
| 1–2 phút | Mở `graph.html`, phóng to và chọn node/edge | Giải thích nhãn cạnh, mô tả, điều kiện và `source_refs` khi có |
| 45–60 giây | Mở `graph.json` và `metadata.json` | Cho thấy output cấu trúc, số node/edge, schema và cảnh báo |
| 30–45 giây | Kết luận phạm vi | Đồ thị là bản nháp của LLM; quan hệ cần được đối chiếu với nguồn |

Khi demo SolarWinds, có thể tìm `Trojanized`, `CNAME`, `TEARDROP`, `credentials`. Chọn một cạnh và đọc các đoạn nguồn ở khung bên phải. Các kỹ thuật trong graph có thể là khả năng của malware hoặc sự kiện quan sát ở một số trường hợp; không ghép toàn bộ thành một chuỗi xảy ra trên mọi nạn nhân.

### Demo phát lại đã kiểm tra trên máy này

```powershell
uv run --no-sync python scripts/demo_online.py --replay "outputs/demo_online/20261002T121844267747Z/response.txt"
```

Lệnh đọc response đã lưu, parse và vẽ lại, không gọi API. Phải thông báo rõ đây là phát lại một kết quả trước đó. Với response CVE phải thêm `--cve`; với Appendix B thêm `--report`; chọn đúng mode và prompt variant của run nguồn. Nếu nguồn hoặc code prompt đã đổi, đối chiếu prompt/hash gốc trước khi coi replay là tái hiện cùng đầu vào.

## 4. Luồng xử lý dùng trong báo cáo

### Nhánh CVE RAG

```text
CVE JSON chính thức
  → đọc description, trích ProductInfo / Platform / ProblemType và version
  → embedding thuộc tính bằng Contriever
  → lưu metadata/description trong SQLite và vector trong file .npy

Tên sản phẩm cần phân tích
  → embedding query
  → so cosine với vector Product / Platform
  → lấy CVE có điểm > MIN_SIMILARITY (0,68)
  → gom description trong giới hạn context (< 3.750 token theo bộ đếm đang dùng)
  → instruction + CVE context
  → LLM sinh JSON nodes / edges
  → parse + kiểm tra cấu trúc
  → graph.json + PNG / SVG / HTML
  → đối chiếu ngữ nghĩa với nguồn
```

Retrieval hiện tại so khớp **Product và Platform**. ProblemType có được trích/lưu embedding nhưng không được dùng để truy hồi trong `get_context()`. Dữ liệu được sắp/lấy theo code hiện có; không mô tả thêm bước top-k hoặc reranking mà repo chưa triển khai. Hashing/heuristic là nhánh kiểm tra offline, không đồng nhất với LLM extraction/Contriever.

### Nhánh threat report / SolarWinds

```text
Báo cáo SolarWinds Appendix C.1
  → tách các đoạn nguồn thành P001, P002, ...
  → instruction chi tiết + nội dung nguồn có ID đoạn
  → LLM sinh nodes / edges / source_refs
  → lưu response.txt
  → parse và kiểm tra schema, ID, endpoint, tham chiếu
  → lưu graph.json
  → bố trí và vẽ → graph.png / graph.svg / graph.html
  → người đọc đối chiếu quan hệ với đoạn nguồn
```

Nhánh report không cần SQLite/vector CVE để tạo prompt. `--paper-prompt` giữ prompt nguyên bản; `--report` dùng nguyên prompt Appendix B. Không áp dụng quy trình gắn ID đoạn của demo SolarWinds cho mọi chế độ.

## 5. Ảnh graph được tạo như thế nào?

**LLM tạo cấu trúc node/edge; Python bố trí và vẽ hình từ cấu trúc đó.**

| Bước | Code chính | Đầu ra / vai trò |
|---|---|---|
| Điều phối demo | `scripts/demo_online.py` | Chọn mode, đọc nguồn, tạo thư mục run, lưu bằng chứng |
| Truy hồi CVE | `src/crystalball/retriever.py::get_context()` | CVE liên quan, similarity và context |
| Tạo prompt CVE | `src/crystalball/generator.py::build_prompt_from_products()` | Instruction ghép với context |
| Gọi model | `src/crystalball/llm/`, `client.complete()` | `response.txt` chứa JSON dạng văn bản |
| Parse | `src/crystalball/postprocess.py::parse_llm_json()` | Bỏ wrapper Markdown khi cần, đọc JSON, có thể repair output bị cắt |
| Kiểm tra | `graph_schema_metrics()` trong `experiment.py` | Trường bắt buộc, ID trùng, endpoint và schema |
| Vẽ | `src/crystalball/demo_graph.py::render_demo_graph()` | NetworkX tính layout; Matplotlib vẽ PNG; code dựng SVG và HTML |

Renderer tách các thành phần liên thông để bố trí, dùng `spring_layout(seed=42)`, điều chỉnh vị trí để giảm chồng node, vẽ nhãn node và cạnh. PNG được xuất ở 120 dpi. SVG chứa đồ họa vector; HTML nhúng SVG và dữ liệu để tìm kiếm, phóng to, kéo khung nhìn và đọc chi tiết. Renderer từ chối ID trùng hoặc cạnh trỏ tới node không tồn tại; không tự thêm cạnh để nối các cụm.

`seed=42` chỉ cố định bước tính layout với dữ liệu tương ứng, không làm response LLM lặp lại giống hệt. Repair JSON có thể giữ được một phần graph nhưng không chứng minh đã khôi phục đầy đủ nội dung.

## 6. File nào đưa vào báo cáo và slide?

Mỗi lần chạy tạo thư mục `outputs/demo_online/<timestamp>/` riêng. Timestamp trong tên thư mục dùng UTC.

| File | Cách sử dụng |
|---|---|
| `graph.png` | Chèn vào báo cáo; hình toàn cảnh hoặc kết quả minh họa |
| `graph.svg` | Chèn vào slide/Word nếu hỗ trợ SVG; phóng to giữ nét |
| `graph.html` | Demo tương tác trực tiếp trong trình duyệt, hoạt động offline |
| `graph.json` | Ví dụ cấu trúc node/edge, phụ lục hoặc kiểm tra kỹ thuật |
| `prompt.txt` | Minh họa cách instruction và context được kết hợp |
| `response.txt` | Bằng chứng đầu ra nguyên gốc, dùng cho replay |
| `metadata.json` | Mode, model khi gọi mới, status, số node/edge, schema, cảnh báo |
| `sources.json` | Đối chiếu ID đoạn với nội dung nguồn ở chế độ SolarWinds |

Hai hình quy trình mới nằm tại `outputs/demo_presentation/luong_he_thong.png` và `luong_tao_anh.png`, có bản SVG cùng tên để chèn vào slide. File `generate_figures.py` trong thư mục đó cho phép tạo lại hình.

Để mở output hoàn tất gần nhất:

```powershell
$demoRun = Get-ChildItem outputs/demo_online -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'graph.html') } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
Invoke-Item (Join-Path $demoRun.FullName 'graph.html')
Get-Content (Join-Path $demoRun.FullName 'metadata.json')
```

### Kết quả đã xác minh offline ngày 12/10/2026

- SolarWinds `--check`: đọc 56 đoạn nguồn và tạo prompt thành công.
- CVE `--cve --check`: dùng index chính thức đã có, tạo prompt với 7 CVE. Không gọi API extraction hoặc generation.
- Replay SolarWinds: **39 nodes, 39 edges**, schema hợp lệ, không repair, không thiếu/không có ID tham chiếu lạ; tạo đủ PNG/SVG/HTML.
- Output replay: `outputs/demo_online/20261012T143848618415Z/`.
- Response nguồn: `outputs/demo_online/20261002T121844267747Z/response.txt`. Metadata run nguồn ghi Gemini `gemini-3.8-flash`; metadata replay ghi `offline_replay` và không có usage/provider mới.

DeepSeek đã qua preflight cấu hình/prompt với reasoning `high` và provider `baidu/fp8`; lần kiểm tra đó không gọi API và chưa có response/graph DeepSeek để đưa vào bảng so sánh.

Ngày 13/10/2026 đã kiểm tra thêm `--report --reasoning high --check --no-open` cho cả ba backend: cùng prompt SHA-256, cùng cap 16.384 token, đều `CHECK OK`. Đây là kiểm tra chuẩn bị đầu vào T0, chưa phải kết quả generation ba mô hình.

Số 39/39 mô tả đúng response này, không phải kết quả cố định của mọi lần chạy. Schema và tham chiếu hợp lệ chưa xác nhận đúng ngữ nghĩa từng cạnh. Replay không giữ provider finish reason/usage mới; cần xem metadata gốc nếu đánh giá việc chạm cap của response nguồn.

## 7. Đoạn có thể đưa vào báo cáo

> Hệ thống CrystalBall hỗ trợ sinh đồ thị tấn công từ hai loại đầu vào: thông tin CVE và báo cáo mối đe dọa. Với nhánh CVE, chương trình trích các thuộc tính lỗ hổng, tạo embedding và lưu metadata cùng vector. Khi nhận danh sách sản phẩm, bộ truy hồi so sánh độ tương đồng cosine để chọn các mô tả CVE liên quan và đưa vào context của prompt. Với nhánh báo cáo, nội dung nguồn được đưa trực tiếp vào prompt. Mô hình ngôn ngữ sinh cấu trúc JSON gồm các nút và cạnh; chương trình hậu xử lý kiểm tra cấu trúc rồi dùng NetworkX và Matplotlib để tạo hình, đồng thời xuất SVG và HTML tương tác. Các quan hệ do mô hình đề xuất cần được đối chiếu với nguồn trước khi dùng để kết luận về đường tấn công.

Chú thích hình demo:

> Hình X. Attack graph SolarWinds/SUNBURST từ response của run `20261002T121844267747Z`, metadata nguồn ghi Gemini `gemini-3.8-flash`, prompt chi tiết `detailed_grounded_v1`; phát lại offline ngày 12/10/2026. Graph có 39 nút và 39 cạnh. Hình minh họa output của pipeline; tính đúng của mọi quan hệ chưa được chuyên gia xác nhận.

Nếu viết số liệu thí nghiệm, lấy từ `REPRODUCTION_REPORT.md`, ghi run/điều kiện/model/số repeat và phạm vi chấm. Không trộn số liệu của một demo với thống kê của run 130 request. Không dùng số node/edge hoặc tỷ lệ parse để gọi là độ chính xác attack graph.

Đoạn mô tả phạm vi ba mô hình ở thời điểm hiện tại:

> Dự án chọn Gemini, GPT-5.6 Luna và DeepSeek làm ba mô hình thay thế để tái hiện các kịch bản của bài báo. Chương trình đã hỗ trợ demo riêng từng mô hình. Kết quả định lượng hiện có thuộc run hai mô hình; bộ thí nghiệm ba mô hình dự kiến sử dụng cùng năm kịch bản, mỗi tổ hợp lặp năm lần, và cần hoàn thiện điều phối batch trước khi thực hiện.

## 8. Dàn ý 7 slide và lời thuyết trình

| Slide | Nội dung | Hình/bằng chứng |
|---|---|---|
| 1. Bài toán | Mục tiêu tái hiện phương pháp và kịch bản bằng Gemini/Luna/DeepSeek | Một đoạn nguồn ngắn; danh sách ba mô hình |
| 2. Kiến trúc | Hai nhánh đầu vào, retrieval chỉ ở nhánh CVE | `luong_he_thong.svg` |
| 3. RAG | Extraction → embedding → cosine → context; tham số 0,68 và 3.750 token | Prompt/meta của CVE `--check` |
| 4. Luồng tạo ảnh | Prompt → LLM JSON → parse → layout → hình | `luong_tao_anh.svg` |
| 5. Demo | Một lần generation T0 hoặc SolarWinds, mở graph tương tác | `graph.html`; dự phòng replay |
| 6. So sánh mô hình | C2/T0 cùng repeat của ba mô hình sau khi có kết quả; hiện ghi DeepSeek chưa chạy | Ba cột Gemini/Luna/DeepSeek; SVG, prompt, metadata; giữ số liệu lịch sử riêng |
| 7. Đánh giá và giới hạn | Schema khác đúng ngữ nghĩa; thiếu điều kiện, truncation, cần review | Cảnh báo metadata và kết luận báo cáo hiện hành |

Lời dẫn khoảng 45 giây:

> “Đầu vào của chương trình có thể là danh sách sản phẩm hoặc báo cáo mối đe dọa. Với danh sách sản phẩm, hệ thống truy hồi những CVE liên quan rồi ghép mô tả vào prompt; với báo cáo SolarWinds, chương trình đưa nội dung nguồn trực tiếp vào prompt. LLM trả về danh sách nút và cạnh dưới dạng JSON. Python kiểm tra cấu trúc, tính bố cục và tạo PNG, SVG, HTML tương tác. Trong demo này, chúng tôi chọn một quan hệ để đối chiếu với đoạn nguồn, vì vẽ được graph chưa đủ chứng minh mọi quan hệ đều đúng.”

## 9. Xử lý lỗi thường gặp

| Hiện tượng | Xử lý |
|---|---|
| Không tìm thấy `uv` | Cài `uv`, mở terminal mới rồi chạy lại |
| Backend `manual` hoặc thiếu key | Chỉnh `.env` cho backend cần dùng; replay không cần key |
| API báo model/permission/quota | Xem lỗi terminal và metadata; dùng output đã lưu để tiếp tục demo |
| CVE thiếu index/vector | Dùng SolarWinds/Appendix B để demo trước; dựng index theo README mục 6 |
| `--check` không có ảnh | Đúng hành vi: mới tạo prompt, chưa có response |
| Graph bị cắt hoặc repaired | Đọc `warnings`, `repaired`, metadata/provider của run gốc; trình bày là graph có thể thiếu |
| Ảnh nhiều node, khó đọc trên slide | Dùng SVG để phóng to và HTML để giải thích một nhóm quan hệ; giữ toàn cảnh trong phụ lục |
| BAT chờ nhấn phím | Đặt `$env:CRYSTALBALL_DEMO_NO_PAUSE='1'`, hoặc chạy script Python trực tiếp |

Không cần chạy lại toàn bộ `run_paired_experiment.py --execute-reproduction` chỉ để lấy ảnh demo. Full runner phục vụ bộ thí nghiệm nhiều request và có quy trình ngân sách riêng.

Để có thống kê ba mô hình, làm theo [kế hoạch thí nghiệm ba mô hình](THI_NGHIEM_BA_MO_HINH.md). Thêm `.env` hoặc chạy ba demo một lần chưa tạo ra bộ batch năm repeat.

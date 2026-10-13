# CrystalBall — tái hiện sinh attack graph bằng RAG

Repo tái hiện phương pháp và các nhóm thí nghiệm §5.1–5.4 của Prapty, Kundu, Iyengar, [Using Retriever Augmented Large Language Models for Attack Graph Generation](https://arxiv.org/abs/2408.05855). CVE hoặc threat report được đưa vào prompt, LLM sinh graph, sau đó code kiểm tra cấu trúc và nhóm đọc bằng chứng để đánh giá ngữ nghĩa.

**Phạm vi hiện tại:** demo và chuẩn bị thí nghiệm bằng **ba mô hình độc lập**, để đối chiếu các nhóm so sánh ba mô hình của bài báo:

| Mô hình | Model ID | Backend để chạy demo |
|---|---|---|
| Gemini | `gemini-3.8-flash` | `gemini` |
| GPT-5.6 Luna | `openai/gpt-5.6-luna` | `openrouter` |
| DeepSeek | `deepseek/deepseek-v4.1-flash` | `openrouter_v2` |

DeepSeek là mô hình thứ ba. Tên backend `openrouter_v2` và các biến `_V2` chỉ phân biệt cấu hình OpenRouter thứ hai đã có, không phải phiên bản của dự án. **Runner chín hình đã hỗ trợ ba mô hình**, mỗi hình một request mặc định; runner đầy đủ §5.1–5.4 vẫn là bộ lịch sử hai mô hình. Xem [runner chín hình và demo online](docs/THI_NGHIEM_BA_MO_HINH.md).

**Bộ chín hình mới:** `outputs/paper_nine/paper9_20261013_original/` có đủ chín response của ba mô hình; `paper9_20261013_reviewed/index.html` là bộ ảnh đã chọn, kèm trang đối chiếu từng hình. Figure 13 có ảnh rút gọn gom nhóm và graph DeepSeek đầy đủ riêng; metadata ghi rõ nguồn/variant của mỗi ảnh.

**Tổ chức output:** xem [outputs/README.md](outputs/README.md) để biết bộ nào dùng cho demo, file nào là bằng chứng và vị trí các bản trung gian trong archive. Các bản thử cũ đã chuyển sang `outputs/archive/20261013_cleanup/`; bộ reviewed, original, run mới hoàn thành và dữ liệu báo cáo lịch sử được giữ ở phần đang dùng.

**Run lịch sử — hai mô hình:** `20260927_full_reproduction` lưu 130 response của Gemini và Luna, mỗi tổ hợp chính lặp 5 lần. Số liệu đã được đánh giá lại offline để sửa lỗi parser và cách diễn giải; nhãn thủ công vẫn là **Codex sơ bộ, chưa được chuyên gia xác nhận**. Đọc [báo cáo số liệu lịch sử](REPRODUCTION_REPORT.md) trước khi trích số liệu.

## 1. Đọc gì, ở đâu?

| Tài liệu / thư mục                                                                                               | Mục đích                                                                                  |
| -------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| [README này](README.md)                                                                                              | Cài đặt, vận hành, phân biệt lệnh offline/API, cách đọc và đánh giá output    |
| [Thí nghiệm ba mô hình](docs/THI_NGHIEM_BA_MO_HINH.md) | Cấu hình Gemini/Luna/DeepSeek, runner chín hình, demo và cách chạy trên máy mới |
| [Demo và trình bày](docs/HUONG_DAN_DEMO_VA_TRINH_BAY.md) | Lệnh chạy, luồng tạo ảnh, file đưa vào báo cáo và dàn ý slide |
| [Đối chiếu chín graph](docs/DOI_CHIEU_9_DO_THI_VA_PHAM_VI_TAI_HIEN.md) | Mapping hình gốc → năm kịch bản, nguồn prompt và hình tái hiện |
| [REPRODUCTION_REPORT.md](REPRODUCTION_REPORT.md)                                                                      | Báo cáo run hai mô hình: thiết kế, số liệu đã sửa, kết luận và giới hạn |
| [E1 — nhất quán với môi trường](experiments/env_consistency/README.md) | Thí nghiệm phụ về thay đổi phiên bản/cấu hình và CVE còn xuất hiện trong graph |
| [H1 — cạnh bám nguồn](experiments/h1_edge_support/README.md) | Thí nghiệm phụ trích cạnh CVE→CVE và chấm mức độ được nguồn hỗ trợ |
| [data/cve_official/manifest.json](data/cve_official/manifest.json)                                                    | Tám CVE chính thức: ID, URL, commit nguồn và SHA-256                                    |
| [data/reproduction/manifest.json](data/reproduction/manifest.json)                                                    | Nguồn Appendix A/B/C, trang PDF, chuẩn hóa văn bản và hash                             |

**Phạm vi chia sẻ:** code vận hành, các file `.bat`, tests, dependency lock, tám CVE chính thức, prompt nguồn Appendix và tài liệu hướng dẫn. Ba bộ `outputs/paper_nine/` đã chọn và hai sơ đồ `outputs/demo_presentation/` cũng có trong Git, gồm prompt/response/metadata và ảnh tham chiếu. DB/vector/cache, archive và bộ 130 response lịch sử giữ cục bộ. Không cần các artifact lịch sử để chạy runner chín hình hoặc tạo run mới; API key nằm trong `.env` riêng của từng người.

## 2. Luồng xử lý và code

```text
CVE JSON → extraction thuộc tính → SQLite + embedding
                                      ↓
Danh sách sản phẩm → retrieval → mô tả CVE liên quan → prompt
Threat report ─────────────────────────────────────→ prompt
                                                        ↓
                                              LLM → raw response
                                                        ↓
                                          parse → graph JSON / PNG
                                                        ↓
                                    kiểm tra cấu trúc + đọc bằng chứng
```

Threat report đi trực tiếp vào prompt, không qua truy hồi CVE. Extraction lấy `ProductInfo`, `Platform`, `ProblemType`; retrieval dùng độ tương đồng với metadata để lấy description. Graph sinh ra vẫn cần kiểm chứng prerequisite và quan hệ nhân quả.

| Thành phần                                       | File chính                                                                                                                                 |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Cấu hình / lưu trữ                             | [config.py](src/crystalball/config.py), [db.py](src/crystalball/db.py)                                                                        |
| Nạp CVE, extraction, embedding                    | [preprocess.py](src/crystalball/preprocess.py), [extractors.py](src/crystalball/extractors.py), [embeddings.py](src/crystalball/embeddings.py) |
| Truy hồi / tạo prompt                            | [retriever.py](src/crystalball/retriever.py), [generator.py](src/crystalball/generator.py)                                                    |
| Client API                                         | [llm/](src/crystalball/llm/)                                                                                                                 |
| Parse / vẽ graph                                  | [postprocess.py](src/crystalball/postprocess.py)                                                                                             |
| Điều phối thí nghiệm, journal và ngân sách | [run_paired_experiment.py](scripts/run_paired_experiment.py)                                                                                 |

Các lệnh chính trong `scripts/`: `ingest_cves.py` nạp dữ liệu; `build_prompt.py` tạo prompt/gọi model; `ingest_response.py` đọc response đã có; `run_paired_experiment.py` điều phối bộ thí nghiệm hai mô hình; `demo_online.py` chọn một trong ba mô hình cho mỗi lần demo; `export_paper_demo.py` vẽ gallery offline từ run lịch sử. Script tạo dữ liệu giả, demo cũ và đánh giá lại riêng run lịch sử đã được lưu cục bộ trong `docs/archive/`.

Thư mục `experiments/` bổ sung E1 và H1, tách khỏi bộ tái hiện §5.1–5.4. Các lệnh chuẩn bị/chấm dùng response đã lưu; `experiments.env_consistency.generate` có gọi API và dùng riêng `OPENAI_API_KEY`, chưa tích hợp cấu hình ba mô hình/provider của demo. E1 chấm theo luật môi trường tự viết, H1 có nhãn sơ bộ do Claude gán; chưa coi các chỉ số này là độ chính xác khai thác thực tế hoặc xác nhận chuyên gia.

## 3. Cài đặt

Các lệnh dưới đây dùng **PowerShell**, chạy tại thư mục repo. Cần Git và `uv`. Project khai báo Python ≥3.10; `.python-version` chọn Python 3.13, là phiên bản đã dùng để kiểm thử. Cài dependency lần đầu cần mạng.

```powershell
git clone https://github.com/Anh26535D/llm-attack-graph-generation.git
Set-Location llm-attack-graph-generation
$env:PYTHONIOENCODING = "utf-8"
uv sync --locked --extra dev
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
uv run --no-sync pytest -q
```

Để chạy Contriever và ba mô hình qua hai dịch vụ API Gemini/OpenRouter, cài thêm:

```powershell
uv sync --locked --extra dev --extra embeddings --extra gemini --extra openrouter --extra paper
```

Dùng `uv run --no-sync` sau khi sync để giữ các extras đã cài. Không cần `tokens` extra cho cấu hình lịch sử: run dùng bộ ước lượng token theo từ. Cài `tiktoken` có thể đổi cách đếm và cắt context; bộ đếm đó cũng không phải tokenizer của cả hai nhà cung cấp.

### Demo online bằng một file BAT trên Windows

**Ưu tiên tái hiện chín hình của bài báo:**

```powershell
.\paper_demo.bat --check --no-open       # Chuẩn bị 9 prompt, không gọi LLM
.\paper_demo.bat                         # Đúng 9 request, 3 mô hình, 1 repeat
.\demo_online.bat --figure 10            # Demo riêng Figure 10 bằng DeepSeek
.\demo_online.bat --nine                 # Demo online cả 9 hình
```

**Chạy trên máy mới:** clone repo, cài `uv`, mở PowerShell tại thư mục repo rồi tạo cấu hình:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
.\paper_demo.bat --resume outputs/paper_nine/paper9_20261013_reviewed --render-only
.\presentation_demo.bat
```

Hai lệnh trên tạo lại ảnh từ response đã lưu và hai sơ đồ quy trình, không gọi API, không cần điền key. Để **sinh chín response mới**, điền `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `OPENROUTER_API_KEY_V2` trong `.env`, giữ model/provider theo mẫu rồi chạy `paper_demo.bat --check --no-open` trước `paper_demo.bat`. Runner chín hình tự chọn backend theo Figure, không cần đổi `LLM_BACKEND` giữa các hình. Khi máy clone không có PDF gốc, runner dùng chín ảnh tham chiếu đã commit và kiểm tra hash trước khi sao chép; không cần DB/vector/index Contriever cho phạm vi này.

Output nằm trong `outputs/paper_nine/<run>/`: ảnh nguồn PDF tách riêng ở `references/`; mỗi hình có `graph.png`, `graph.svg`, `graph.html`, `comparison.html`, prompt/response và metadata trong `figures/figure_NN_r01/`. `index.html` tập hợp chín trường hợp. Nút tròn, tên nút đặt bên ngoài, toàn bộ tên cạnh hiện trên ảnh; không xóa hoặc thêm quan hệ để làm giống hình gốc.

Để chỉnh bố cục từ response đã có mà không gọi API:

```powershell
uv run --no-sync python scripts/run_paper_experiment.py --resume outputs/paper_nine/RUN_ID --render-only --layout-seed 17
```

Chế độ dưới đây vẫn có cho demo SolarWinds chi tiết, RAG hoặc Appendix B riêng lẻ:

Nhấp đúp `demo_online.bat`, hoặc chạy `./demo_online.bat` trong PowerShell.
Script cài/kiểm tra dependency bằng `uv`, đọc cấu hình `.env`, dùng **báo cáo
SolarWinds đầy đủ ở Appendix C.1** và gọi **một request API** để sinh graph chi tiết.
Đây là cùng case study với hình SolarWinds trong bài; CVE RAG được chọn riêng bằng `--cve`.
Trong `.env`, đặt `LLM_BACKEND=gemini`, `openrouter` hoặc `openrouter_v2`, API key và model tương ứng.
`.env` được ưu tiên hơn biến môi trường còn sót lại từ demo offline.

Kết quả mỗi lần chạy nằm riêng trong `outputs/demo_online/<timestamp>/`:
`prompt.txt`, `response.txt`, `metadata.json`, `sources.json`, `graph.json`,
`graph.png`, `graph.svg`, `graph.html`. Bản HTML tự mở, hoạt động offline,
cho phép kéo/phóng to, tìm nút, xem nhãn cạnh và nhấn nút/cạnh để đọc chi tiết cùng đoạn nguồn.
PNG và SVG giữ đầy đủ nhãn nút/cạnh; màu phân biệt tấn công, né tránh, phát hiện và giảm thiểu.
Giữ cửa sổ terminal để xem lỗi nếu có.
Request có thể tính phí; đây là demo một lần, không dùng budget của full runner.

Mặc định dùng prompt chi tiết bổ sung yêu cầu bám nguồn và giới hạn output 16.384 token,
reasoning medium cho Gemini/Luna và high cố định cho DeepSeek. Đây là biến thể demo, không phải prompt nguyên bản của bài báo.
Dùng `--paper-prompt` để giữ nguyên prompt Appendix. Script không thêm nút/cạnh để đạt
số lượng; số nút phụ thuộc nội dung và mô hình. Tham chiếu đoạn nguồn chỉ giúp kiểm toán,
chưa phải chứng minh quan hệ đúng. Output bị cắt/repair được báo riêng, không tự gọi lại API.

```powershell
.\demo_online.bat                         # SolarWinds đầy đủ, graph chi tiết
.\demo_online.bat --backend openrouter    # GPT-5.6 Luna
.\demo_online.bat --backend openrouter_v2 # DeepSeek, mô hình thứ ba
.\demo_online.bat --paper-prompt          # SolarWinds với prompt nguyên bản của bài
.\demo_online.bat --evasion               # Chuyên sâu phần né tránh phát hiện
.\demo_online.bat --cve                   # CVE RAG, cần index Contriever đã dựng
.\demo_online.bat --report                # Appendix B, không cần index/Contriever để tạo prompt
.\demo_online.bat --check --no-open       # Kiểm tra prompt, không gọi LLM API
.\demo_online.bat --replay "outputs/demo_online/RUN_ID/response.txt"  # Vẽ lại SolarWinds, không gọi API
```

Demo SolarWinds mặc định không cần index hoặc tải Contriever. Để dùng `--cve`, dựng index theo mục 6.

Mô hình thứ ba DeepSeek chỉ cần ba biến trong `.env`:

```dotenv
OPENROUTER_API_KEY_V2=YOUR_API_KEY
OPENROUTER_MODEL_V2=deepseek/deepseek-v4.1-flash
OPENROUTER_PROVIDER_CONFIG_V2='{"only":["baidu/fp8"],"allow_fallbacks":false}'
```

Chạy `uv run --no-sync python scripts/demo_online.py --backend openrouter_v2`,
hoặc dùng BAT như trên. Reasoning của DeepSeek cố định `high` trong code
(`OPENROUTER_V2_REASONING_LEVEL` ở `config.py`), không cần thêm biến môi trường.
Muốn đổi nhà cung cấp, sửa slug trong `only`. Dùng `--check --no-open` để kiểm tra
cấu hình và tạo prompt mà không gọi API; kết hợp được với `--report`, `--cve`, `--evasion`.

Để demo cùng prompt Appendix B trên cả ba mô hình (mỗi lệnh một request):

```powershell
uv run --no-sync python scripts/demo_online.py --backend gemini --report --reasoning high
uv run --no-sync python scripts/demo_online.py --backend openrouter --report --reasoning high
uv run --no-sync python scripts/demo_online.py --backend openrouter_v2 --report --reasoning high
```

Thêm `--check --no-open` để chỉ chuẩn bị, không gọi LLM API. Mỗi lần lưu output riêng;
đây là một repeat minh họa, chưa phải bộ thí nghiệm năm repeat. Xem [thiết kế ba mô hình](docs/THI_NGHIEM_BA_MO_HINH.md)
cho ánh xạ chín hình → năm kịch bản; runner mới mặc định **9 response**, `--repeat 5` là 45 response. C1/X0/§5.4 không nằm trong runner này.

Chế độ report dùng nguyên prompt Appendix B, không bọc thêm instruction.
Để chạy không chờ phím trong terminal tự động, đặt `$env:CRYSTALBALL_DEMO_NO_PAUSE="1"`.

## 4. Chạy demo không gọi API

Luồng này dùng **tám record CVE chính thức có sẵn trong repo**, với heuristic extraction và hashing để chạy không cần model/key. Đặt rõ cấu hình ngay cả khi `.env` đang có backend thật.

```powershell
$env:LLM_BACKEND = "manual"
$env:EXTRACTOR_BACKEND = "heuristic"
$env:EMBEDDING_BACKEND = "hashing"
$env:CRYSTALBALL_DB_PATH = "$PWD/data/db/demo.sqlite3"
$env:CRYSTALBALL_EMBEDDINGS_DIR = "$PWD/data/embeddings/demo"
uv run --no-sync python scripts/ingest_cves.py --input data/cve_official
uv run --no-sync python scripts/build_prompt.py --products "Oculus Desktop" "Jetson TX1" "Raspberry Pi"
```

Kết quả mong đợi: ingest tám CVE (file `manifest.json` được bỏ qua vì không phải record CVE), sau đó in prompt và ghi `outputs/prompts/prompt_*.txt` cùng metadata. Chưa có graph do chưa gọi LLM. Heuristic/hashing chỉ kiểm tra luồng code, không tái hiện kết quả extraction/Contriever của báo cáo.

Các biến `$env:...` ưu tiên hơn `.env` và còn hiệu lực trong cùng terminal. **Mở terminal mới** trước khi chuyển sang cấu hình thí nghiệm chính.

## 5. Chạy từng bước với dữ liệu của nhóm

Ở chế độ `LLM_BACKEND=manual`, chỉ tạo prompt rồi nhập response đã có:

```powershell
uv run --no-sync python scripts/build_prompt.py --products "Oculus Desktop" "Jetson TX1" "Raspberry Pi"
uv run --no-sync python scripts/build_prompt.py --report path/to/report.txt
# Thay hai đường dẫn dưới đây bằng file thực tế của bạn.
uv run --no-sync python scripts/ingest_response.py --response path/to/answer.txt --prompt-file outputs/prompts/prompt_ID.txt --backend manual
```

Hai lệnh tạo prompt ghi vào `outputs/prompts/`; chế độ sản phẩm cần DB/vector đã ingest. Chế độ report cần thay `path/to/report.txt` bằng báo cáo văn bản của bạn. `ingest_response.py` parse response thành JSON/PNG trong `outputs/graphs/`, không gọi API. Các file trong `data/reproduction/` đã có prompt wrapper của bài báo; dùng runner ở mục 6 để giữ prompt đúng, không truyền chúng vào `--report` rồi thêm wrapper lần nữa.

Với bộ CVE riêng, dùng thư mục phẳng chứa CVE Record Format v5 và DB/vector riêng:

```powershell
uv run --no-sync python scripts/ingest_cves.py --input path/to/cve_folder
```

`ingest_cves.py` quét `*.json` trực tiếp trong thư mục, không quét đệ quy. Chọn `CRYSTALBALL_DB_PATH` và `CRYSTALBALL_EMBEDDINGS_DIR` trước khi chạy; giữ nguyên chúng khi build prompt. Không trộn hashing và Contriever trong cùng index. Ingest tổng quát này không tạo manifest index mà runner thí nghiệm chính yêu cầu.

**Lệnh có thể tính phí:** `ingest_cves.py` khi `EXTRACTOR_BACKEND=llm`; `build_prompt.py` khi `LLM_BACKEND` là `gemini`, `openrouter`, `openrouter_v2` hoặc `openai`. Các lệnh riêng lẻ này không dùng bộ giới hạn ngân sách 50.000 VND của full runner.

## 6. Runner lịch sử §5.1–5.4 — hai mô hình

Mục này mô tả runner đã dùng cho run 130 response, **không tự chạy DeepSeek** dù `.env` có cấu hình mô hình thứ ba. Để chạy phần tái hiện chín hình bằng ba mô hình, dùng `run_paper_experiment.py` ở mục demo và [hướng dẫn chín hình](docs/THI_NGHIEM_BA_MO_HINH.md). Runner mới lưu báo cáo riêng, không gọi bộ tạo báo cáo lịch sử còn ghi cứng kết luận T0 cũ.

### Cấu hình

Sửa `.env` cục bộ, không commit key:

```dotenv
LLM_BACKEND=gemini
GEMINI_API_KEY=
GEMINI_MODEL=gemini-3.8-flash
OPENROUTER_API_KEY=
OPENROUTER_MODEL=openai/gpt-5.6-luna
EXTRACTOR_BACKEND=llm
EMBEDDING_BACKEND=sentence-transformers
EMBEDDING_MODEL=facebook/contriever-msmarco
MIN_SIMILARITY=0.68
CONTEXT_TOKENS_PER_QUERY=3750
```

Điền hai key chỉ khi chuẩn bị chạy API. Full runner kiểm tra đúng hai model trên và chạy cả hai, dù `LLM_BACKEND=gemini` chỉ định backend extraction. Model ID là cấu hình của run đã lưu, không phải cam kết về khả năng truy cập API trong tương lai. Contriever có thể phải tải model lần đầu.

| Điều kiện     | Input / mục đích                                                                             |   Số request |
| ---------------- | ----------------------------------------------------------------------------------------------- | ------------: |
| C0               | Baseline theo §5.1: Raspberry Pi, Oculus Desktop, Jetson Nano; không context                  |            10 |
| C1               | Query Oculus Desktop, Jetson TX1, Raspberry Pi; context từ Contriever                          |            10 |
| C2               | Prompt Appendix A với đủ tám mô tả CVE                                                    |            10 |
| T0               | Appendix B: PostgreSQL và container/application RCE                                            |            10 |
| T1               | Toàn bộ prompt/report SolarWinds Appendix C.1                                                 |            10 |
| T2               | Prompt/report SolarWinds evasion Appendix C.2                                                   |            10 |
| X0               | Instruction/schema tương ứng nhưng thiếu cả CVE context và mô tả hệ thống mục tiêu |            10 |
| §5.4 chia/gộp  | Hai chunk × hai model × năm lần; gộp cục bộ                                              |            20 |
| §5.4 tiếp tục | Cắt ngắn output rồi yêu cầu continuation                                                   |            20 |
| §5.4 mở rộng  | Edge detail và edge context                                                                    |            20 |
| **Tổng**  | 70 request chính + 60 request §5.4                                                            | **130** |

Pilot C1 nằm trong 70 request, không cộng thêm. C0 khác C1 cả tên Jetson và instruction. X0 không giữ target system, nên **không phải phép đo riêng tác dụng của context**. Không dùng so sánh này để suy luận nhân quả về RAG.

### Trình tự trên máy mới

Đọc kết quả đã lưu không cần DB, embedding hoặc API. Nếu muốn chạy một đợt mới, cần index trước. DB/vector/cache không được chia sẻ qua Git.

**Bước 1 — dựng index, có thể gọi API extraction:** sau khi người phụ trách duyệt ngân sách mới, chạy với run ID mới. Khi chưa có index, lệnh này gọi extraction cho tám CVE rồi dừng trước graph generation.

```powershell
uv run --no-sync python scripts/run_paired_experiment.py --dataset-manifest data/cve_official/manifest.json --prepare-only --run-id team_index_01
```

Đây là nhánh bootstrap/legacy: chi phí extraction của nó **không được cộng tự động** vào budget của full run kế tiếp. Nhóm phải tính cả khoản này khi duyệt tổng ngân sách. Run lịch sử đã reuse index nên không phát sinh extraction mới trong 130 request. Dựng lại index bằng LLM có thể cho metadata khác và kéo theo retrieval khác.

**Bước 2 — kiểm tra và khóa prompt, không gọi LLM API:** `--dry-run` cũng yêu cầu index đã sẵn sàng; không phải lệnh bootstrap.

```powershell
uv run --no-sync python scripts/run_paired_experiment.py --dataset-manifest data/cve_official/manifest.json --dry-run
uv run --no-sync python scripts/run_paired_experiment.py --dataset-manifest data/cve_official/manifest.json --prepare-reproduction --run-id team_reproduction_01
```

Kiểm tra manifest, CVE truy hồi, prompt text/hash, token caps và số request trong `outputs/experiments/team_reproduction_01/`. Chỉ đổi model, scope, schema, cách lấy mẫu hoặc ngân sách sau khi người phụ trách duyệt.

**Bước 3 — chạy API sau khi duyệt prompt và dự toán:**

```powershell
uv run --no-sync python scripts/run_paired_experiment.py --dataset-manifest data/cve_official/manifest.json --execute-reproduction team_reproduction_01
```

Runner lưu journal trước/sau từng request, response và usage; kiểm tra chi phí ước lượng trước khi gửi. Trần `BUDGET_VND=50000` và bảng giá/tỷ giá được ghi cố định trong script cho run lịch sử. Đây là giới hạn theo run và giá ước lượng, không phải hạn mức tài khoản của nhà cung cấp; cần kiểm tra lại dự toán trước đợt mới. Không tự tăng trần, đổi model hoặc gọi bù ngoài runner.

### Khi có lỗi

- Đọc `manifest.json` và `calls/<call_id>.json` trước; gọi lại `--execute-reproduction` cho cùng run sẽ dùng trạng thái đã lưu, không xóa run để chạy lại.
- Runner không retry tự động. Chỉ với lỗi đã xác nhận transient, dùng `--run-id team_reproduction_01 --retry-transient-call CALL_ID --confirm-transient` cùng `--dataset-manifest`. Giới hạn bốn retry cho toàn run; saved response hoặc trạng thái chưa biết request đã gửi hay chưa không được gửi lại tùy tiện.
- Lỗi `index ... not ready`: làm bước bootstrap hoặc kiểm tra bộ DB/vector/manifest đúng dataset. Không sửa hash để vượt kiểm tra.
- Lỗi output directory đã tồn tại: dùng tên run mới. Bước prepare có thể đã tạo thư mục trước khi phát hiện index chưa sẵn sàng.
- Response bị cắt: giữ raw và finish reason; parse/repair được không có nghĩa là graph đầy đủ. Thay token cap hoặc chạy bù là thay đổi thí nghiệm cần duyệt.

## 7. Đọc artifact và đánh giá

Sau khi chạy bộ thí nghiệm mới, đọc `outputs/experiments/<run_id>/`. Thư mục này được tạo trên máy chạy, không có sẵn trong bản clone:

| Đường dẫn | Cách dùng |
|---|---|
| `manifest.json` | Dataset, cấu hình, prompt hash, kế hoạch và trạng thái run |
| `prompts/`, `call_prompts/` | Prompt cố định và prompt phụ thuộc output ở từng request |
| `calls/` | Journal theo `call_id`: status, usage, finish reason, chi phí |
| `raw_responses/` | Response nguyên bản để đối chiếu parser |
| `graphs/`, `derived/` | Graph đã parse và các graph gộp |
| `metrics.json`, `metrics.csv`, `summary.json` | Kết quả tự động; đối chiếu raw trước khi diễn giải |
| `coverage.*`, `evidence_table.md`, `REPRODUCTION_REPORT.md` | Chỉ báo và báo cáo tự sinh sơ bộ, cần người đọc bằng chứng |

Ví dụ `graph.gemini.C1.r01.a01` là stage graph, Gemini, C1, repeat 1, attempt 1. Đối chiếu cùng ID giữa journal, raw response và hàng metrics. Riêng run lịch sử `20260927_full_reproduction`, bộ đánh giá đã sửa nằm trong `offline_reevaluation/` cục bộ; báo cáo tổng hợp đi kèm repo đã dùng bộ số liệu mới đó.

Đánh giá theo bốn tầng, không gộp thành một điểm “đúng”:

1. **Request/parse:** có response không; JSON hợp lệ trực tiếp, bỏ Markdown, bóc wrapper hay phải sửa phần bị cắt? Kiểm tra riêng finish reason của provider.
2. **Schema/cấu trúc:** đủ trường, ID không trùng, endpoint tồn tại, graph có node/edge, path có hướng liên tục. Schema được kiểm theo chuẩn của repo; prompt C0/T0 không yêu cầu toàn bộ chuẩn này.
3. **Sự kiện:** đọc đủ node label, description/details, pre/postcondition và edge. Dò từ khóa chỉ là tín hiệu tìm mẫu; outcome có thể nằm trong node thay vì edge riêng.
4. **Ngữ nghĩa edge/path:** trích nguồn và locator, kiểm tra prerequisite, host/version, reachability, privilege và điều kiện nối hai CVE. Ghi “được hỗ trợ”, “có điều kiện”, “không được hỗ trợ” hoặc “thiếu”; người duyệt quyết định kết luận cuối.

Mẫu của run lịch sử: census 20 nhánh T0; 24 stratum CVE; 56 quan sát event-output SolarWinds. Quy tắc chọn mẫu được mô tả trong [báo cáo hiện hành](REPRODUCTION_REPORT.md). Không suy rộng các tỷ lệ này thành accuracy toàn bộ graph hoặc xếp hạng model. Số node/edge chỉ mô tả kích thước, không đo chất lượng.

Với run mới, ghi riêng bảng chấm gồm `call_id`, sự kiện/quan hệ, locator node/edge, trích nguồn, prerequisite, nhãn sơ bộ và quyết định của người duyệt. Duyệt tiêu chí và cách lấy mẫu trước khi chấm. Báo cáo runner tự sinh không thay thế bước đọc bằng chứng này.

## 8. Kiểm thử và quy tắc bàn giao

```powershell
uv run --no-sync pytest -q
uv run --no-sync python -m compileall -q src scripts
```

Tests kiểm tra code bằng dữ liệu giả/lưu sẵn, không xác nhận chất lượng ngữ nghĩa của attack graph và không gọi API trả phí. Test riêng cho script đánh giá run cũ được lưu cùng script trong archive; bộ tests được push kiểm tra code đang vận hành.

Giữ nguyên raw response, prompt và journal của run đã công bố; sửa đánh giá ở bộ derived riêng và ghi lý do. Kế hoạch, nhật ký Review 3 và báo cáo gốc trong run được giữ để truy vết; khi mâu thuẫn số liệu, dùng báo cáo hiện hành và bộ `offline_reevaluation`. Không tự chuyển trạng thái review cũ sang bản mới. Mọi đợt API mới, thay phạm vi hoặc nâng nhãn thành chuyên gia xác nhận cần người phụ trách quyết định.

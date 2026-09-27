# CrystalBall — tái hiện sinh attack graph bằng RAG

Repo tái hiện phương pháp và các nhóm thí nghiệm §5.1–5.4 của Prapty, Kundu, Iyengar, [Using Retriever Augmented Large Language Models for Attack Graph Generation](https://arxiv.org/abs/2408.05855). CVE hoặc threat report được đưa vào prompt, LLM sinh graph, sau đó code kiểm tra cấu trúc và nhóm đọc bằng chứng để đánh giá ngữ nghĩa.

**Kết quả hiện có:** run `20260927_full_reproduction` đã lưu 130 response, dùng Gemini `gemini-3.8-flash` và GPT-5.6 Luna qua OpenRouter (`openai/gpt-5.6-luna`), mỗi tổ hợp chính lặp 5 lần. Đây là mô hình thay thế mô hình trong bài báo. Kết quả đã được đánh giá lại offline để sửa lỗi parser và cách diễn giải; nhãn thủ công vẫn là **Codex sơ bộ, chưa được chuyên gia xác nhận**. Đọc [báo cáo hiện hành](REPRODUCTION_REPORT.md) trước khi trích số liệu.

## 1. Đọc gì, ở đâu?

| Tài liệu / thư mục                                                                                               | Mục đích                                                                                  |
| -------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| [README này](README.md)                                                                                              | Cài đặt, vận hành, phân biệt lệnh offline/API, cách đọc và đánh giá output    |
| [REPRODUCTION_REPORT.md](REPRODUCTION_REPORT.md)                                                                      | Báo cáo tổng hợp hiện hành: thiết kế, số liệu đã sửa, kết luận và giới hạn |
| [data/cve_official/manifest.json](data/cve_official/manifest.json)                                                    | Tám CVE chính thức: ID, URL, commit nguồn và SHA-256                                    |
| [data/reproduction/manifest.json](data/reproduction/manifest.json)                                                    | Nguồn Appendix A/B/C, trang PDF, chuẩn hóa văn bản và hash                             |

**Phạm vi bản Git:** code vận hành, tests, dependency lock, tám CVE chính thức, prompt nguồn Appendix và hai tài liệu chính. Raw response, output từng đợt, DB/vector/cache và `docs/archive/` giữ cục bộ, không nằm trong bản clone. Muốn kiểm toán lại run lịch sử cần xin bộ bằng chứng từ người phụ trách; không cần bộ đó để chạy pipeline hoặc tạo run mới.

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

Thư mục `scripts/` chỉ có bốn lệnh: `ingest_cves.py` nạp dữ liệu; `build_prompt.py` tạo prompt/gọi model; `ingest_response.py` đọc response đã có; `run_paired_experiment.py` điều phối bộ thí nghiệm. Script tạo dữ liệu giả, demo cũ và đánh giá lại riêng run lịch sử đã được lưu cục bộ trong `docs/archive/`.

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

Để chạy Contriever và hai API backend, cài thêm:

```powershell
uv sync --locked --extra dev --extra embeddings --extra gemini --extra openrouter
```

Dùng `uv run --no-sync` sau khi sync để giữ các extras đã cài. Không cần `tokens` extra cho cấu hình lịch sử: run dùng bộ ước lượng token theo từ. Cài `tiktoken` có thể đổi cách đếm và cắt context; bộ đếm đó cũng không phải tokenizer của cả hai nhà cung cấp.

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

**Lệnh có thể tính phí:** `ingest_cves.py` khi `EXTRACTOR_BACKEND=llm`; `build_prompt.py` khi `LLM_BACKEND` là `gemini`, `openrouter` hoặc `openai`. Các lệnh riêng lẻ này không dùng bộ giới hạn ngân sách 50.000 VND của full runner.

## 6. Bộ thí nghiệm §5.1–5.4

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

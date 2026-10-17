# Pilot: cùng prompt C2, 10 generation mới, paired validation

Runner: `scripts/run_validation_experiment.py`. Khác runner chín hình: chỉ dùng
một case C2 và một model generation, lặp 10 lần. Không ép 11 node/9 cạnh.
Không sửa graph cho giống hình tham chiếu, không chọn lại repeat đẹp nhất.

Run đầu: `outputs/validation_experiments/c2_10_20261016_01/`. `PROTOCOL.md` và
manifest được ghi trước request đầu tiên. Prompt, dataset và code validator
được hash; settings chỉ được ghi model/backend/options, không ghi API keys.

## Cách chạy

PowerShell từ repo, dùng môi trường đã cài SDK Gemini:

```powershell
.\.venv\Scripts\python.exe scripts/run_validation_experiment.py prepare --out outputs/validation_experiments/MY_RUN --repeats 10
.\.venv\Scripts\python.exe scripts/run_validation_experiment.py generate --out outputs/validation_experiments/MY_RUN
.\.venv\Scripts\python.exe scripts/run_validation_experiment.py validate --out outputs/validation_experiments/MY_RUN
.\.venv\Scripts\python.exe scripts/run_validation_experiment.py report --out outputs/validation_experiments/MY_RUN
```

`prepare` và `report` không gọi API. `generate` gọi đúng một request mới cho mỗi
repeat chưa có response, không retry tự động. Default Gemini medium, cap 8192.
`validate` chạy validator hiện có: Gemini low, cap 4096, tối đa 30 review mỗi
repeat. Các default được freeze trong manifest, không sửa `.env`.

SDK retries tắt. Nếu generation lỗi, `generate --retry-errors` cho phép thử lại
chỉ các repeat thiếu response; các attempts cũ vẫn được tính usage. Nếu hybrid
lỗi/cắt/schema sai, `validate --retry-incomplete` giữ report attempt cũ và dùng
cache riêng repeat để không gọi lại những edge reviews đã thành công. Không
coi call cap, cache hit hay review lỗi là một đánh giá ngữ nghĩa đã hoàn tất.

## Đọc output

Nếu đổi cấu hình validator trong `.env` sau khi đã sinh graph, tạo một lượt
review riêng để giữ cố định mười graph đầu vào và không trộn các cấu hình:

```powershell
.\.venv\Scripts\python.exe scripts/run_validation_experiment.py fork-review --source outputs/validation_experiments/c2_10_20261016_01 --out outputs/validation_experiments/c2_10_20261016_high_9999_01
.\.venv\Scripts\python.exe scripts/run_validation_experiment.py validate --out outputs/validation_experiments/c2_10_20261016_high_9999_01
.\.venv\Scripts\python.exe scripts/run_validation_experiment.py report --out outputs/validation_experiments/c2_10_20261016_high_9999_01
```

`fork-review` chỉ sao chép graph/response/annotation theo byte và freeze config
hiện tại từ `.env`; yêu cầu mode hybrid và `VALIDATOR_LLM_ENABLED=true`.
Generation metadata gốc ở `generation_source.json`; số generation API của lượt
review mới là 0, vì mười request trước đã được tính ở source run. Cache theo
root trong `.env`, tách thêm tên run và repeat. Không nhập nhận xét LLM cũ vào
lượt cấu hình mới. Nhật ký `validation/call_journal/` ghi prompt và kết quả ngay
sau mỗi review; request bị ngắt có chi phí chưa xác định được đánh dấu riêng.

- `index.html`: mười cặp hình original/hybrid, cùng renderer và layout.
- `runs/rNN/response.txt`, `generation.json`, `graph.json`: output generation.
- `runs/rNN/annotation_blind.json`: template để người khác chấm, tạo trước hybrid.
- `runs/rNN/validation/`: report và ảnh từ validator hiện có; original byte-exact.
- `metrics.csv`, `summary.json`, `REPORT.md`: bảng từng repeat và tổng hợp.
- `topology_comparison.json`: Jaccard giữa các cặp repeat trên cặp CVE đã mapping;
  không đo độ đúng và không bao gồm semantics của label.

`validated_graph.json` là audit view giữ mọi cạnh, bổ sung status. Policy retained
chỉ bỏ unsupported/contradicted; `strict_graph.json` chỉ giữ supported. Không có
evidence môi trường thì nhiều cạnh vẫn conditional/unknown. Không nới rules chỉ
để tạo khác biệt giữa before/after. B offline và C hybrid cùng một baseline.

## Thang đo

Nếu gặp MAX_TOKENS và đã tăng giới hạn, chỉ thử lại các review chưa hoàn tất:

```powershell
.\.venv\Scripts\python.exe scripts/run_validation_experiment.py validate --out outputs/validation_experiments/c2_10_20261016_high_9999_01 --retry-incomplete --retry-output-tokens 16384
```

Limit mới được ghi thành `retry_profile_16384.json` và `request_overrides` trong
từng result. Review thành công ở profile ban đầu vẫn dùng cache; response mới
dùng cache key có limit mới. Lỗi lần đầu và token của mọi lần thử vẫn được tính.
Tăng token không khắc phục JSON bọc Markdown hoặc trích dẫn sai; không tự nới
parser hay đổi tiêu chí ngữ nghĩa giữa chừng để làm tăng tỷ lệ pass.

Chính: candidate-edge precision trên nhãn độc lập, kèm recall, F1 và số lỗi giữ/
loại nhầm. Cần công bố độ phủ annotation và tiêu chí đúng/sai. Recall chỉ tính
trong các candidate của original, không tính các quan hệ generator bỏ sót.

Chưa có nhãn độc lập thì precision/recall/F1 = N/A. Không dùng LLM reviewer, rule
labels hay nhãn tự gán của AI để điền vào gold chuyên gia. Unknown/conditional
không tự động là false. Các chỉ số coverage, mapping, trạng thái, biến thiên và
cost vẫn báo được nhưng không gọi là accuracy.

Muốn bổ sung gold sau run: copy annotation template, bỏ các candidate chưa thể
phân xử khỏi `labels`, điền boolean cho các candidate được adjudicate, ghi
`independent=true`, `label_source=human` hoặc `independent_dataset`, provenance
độc lập và graph hash khớp. Lưu `gold/rNN.json` dưới thư mục run rồi chạy `report`.
Lệnh này chỉ tính lại metrics offline vào `evaluation_with_gold.json`, không gọi
API và không thay report validation ban đầu. Nhãn chưa chuyên gia duyệt phải
được mô tả đúng nguồn gốc, không gắn `human` nếu là AI.

10 repeats cùng một case chỉ đo biến thiên trong case đó, chưa phải độ chính
xác của toàn project hoặc xác nhận exploit ngoài thực tế.

## So sánh reviewer trên cùng graph

Backend validation độc lập với backend sinh graph:

| Reviewer | VALIDATOR_LLM_BACKEND | Biến chọn model |
|---|---|---|
| Gemini | gemini | GEMINI_MODEL |
| DeepSeek | openrouter_v2 | OPENROUTER_MODEL_V2 |
| GPT qua OpenRouter | openrouter | OPENROUTER_MODEL |

Để giữ `.env` đang chọn DeepSeek nhưng chạy thêm GPT, dùng override khi tạo
lượt review. Mỗi lượt giữ nguyên 10 graph và tạo cache/report riêng:

```powershell
.\.venv\Scripts\python.exe scripts/run_validation_experiment.py fork-review --source outputs/validation_experiments/c2_10_20261016_01 --out outputs/validation_experiments/MY_GPT_REVIEW --review-backend openrouter --review-tokens 9999 --review-reasoning high
.\.venv\Scripts\python.exe scripts/run_validation_experiment.py validate --out outputs/validation_experiments/MY_GPT_REVIEW
.\.venv\Scripts\python.exe scripts/compare_validation_reviewers.py --runs GEMINI_REVIEW_DIR DEEPSEEK_REVIEW_DIR GPT_REVIEW_DIR --out COMPARISON_DIR
```

Giới hạn calls tính cộng dồn cả retry trong từng repeat. Runner dừng khi gặp
API error và ghi các cạnh còn lại là deferred, không tiếp tục gửi request lỗi.
Lượt bị ngắt có request chưa xác định chi phí được ghi riêng; không tự gọi lại.

Báo cáo so sánh kiểm tra graph bytes, evidence, offline baseline, prompt review
và layout giống nhau. Xem cả đề xuất LLM lẫn nhãn cuối qua policy: hai reviewer
có thể đề xuất khác nhau nhưng bị policy giữ cùng nhãn offline. Tỷ lệ review
hợp lệ chỉ đo định dạng/identity/quote, không phải tỷ lệ cạnh đúng. Không xếp
hạng accuracy nếu chưa có gold độc lập.

`OPENROUTER_PROVIDER_CONFIG_V2` chọn provider cho DeepSeek, tách khỏi biến
backend. Ví dụ `{"only":["coreweave/fp8"],"allow_fallbacks":false}` khóa
CoreWeave; `baidu/fp8` khóa Baidu. Đổi provider nên fork một lượt review riêng,
giữ kết quả cũ để không trộn các điều kiện. Provider được freeze trong manifest
của lượt mới, request metadata ghi cả provider thực tế. Cũng có thể dùng
`--review-provider-config` với JSON để override trong lệnh, không sửa `.env`.

Nếu cần giữ provider nhưng giảm tốc độ, dùng:

```powershell
.\.venv\Scripts\python.exe scripts/resume_slow_validation.py --out REVIEW_RUN_DIR --interval 60
```

Lệnh này resume bằng cache, mỗi bước tối đa một request mới, cách nhau ít nhất
60 giây; không tự nâng call budget. Rate limit của shared pool vẫn có thể xuất
hiện. Khi đổi provider, dừng lượt cũ trước khi chạy lượt mới.

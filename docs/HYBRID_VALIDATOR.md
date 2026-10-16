# Hybrid Evidence-grounded Attack Graph Validator

Module `crystalball.validation` kiểm chứng graph CrystalBall đã lưu, không sinh graph mới, không thực thi exploit. Ảnh chính: [Figure 7 Before/After](../outputs/validator/figure_07_offline/comparison.png), [SVG](../outputs/validator/figure_07_offline/comparison.svg). Hai panel dùng cùng node set, từng edge instance và một layout xác định; cạnh bị bác bỏ vẫn được vẽ đỏ và gắn X.

## Cài đặt và chạy

Từ thư mục gốc, dùng Python >=3.10. PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,paper]"
.\.venv\Scripts\python.exe -m crystalball.validation --mode offline --out outputs/validator/figure_07_offline
.\.venv\Scripts\python.exe -m pytest -q
```

Lệnh offline tạo đủ ảnh, không khởi tạo client API kể cả khi `.env` bật LLM. Không cần SDK Gemini/OpenAI cho lệnh này. Có thể chỉ định graph C2 khác:

```powershell
.\.venv\Scripts\python.exe -m crystalball.validation --mode offline --graph outputs/paper_nine/paper9_20261013_original/figures/figure_09_r01/graph.json --out outputs/validator/figure_09_offline
.\.venv\Scripts\python.exe -m crystalball.validation --mode offline --graph outputs/paper_nine/paper9_20261013_original/figures/figure_10_r01/graph.json --out outputs/validator/figure_10_offline
```

Review API chỉ chạy khi đồng thời `mode=hybrid` và `llm_enabled=true`. Mặc định code là `false`. Chọn model qua biến model của backend, độc lập với `LLM_BACKEND` của generation:

| Backend Validator | Key và model tái sử dụng |
| --- | --- |
| `gemini` | `GEMINI_API_KEY`, `GEMINI_MODEL` |
| `openai` | `OPENAI_API_KEY`, `OPENAI_MODEL` |
| `openrouter` | `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` |
| `openrouter_v2` | `OPENROUTER_API_KEY_V2`, `OPENROUTER_MODEL_V2`, `OPENROUTER_PROVIDER_CONFIG_V2` |

Không thay đổi `LLM_BACKEND` toàn cục. Adapter dùng bản sao `Settings` và `LLMClient` hiện có; truyền riêng giới hạn output và reasoning cho từng request. OpenAI client bổ sung nhận các override này và ghi usage; chế độ generation gọi `complete(prompt)` vẫn giữ nguyên payload cũ. Với model OpenAI không hỗ trợ reasoning, không gửi trường `reasoning_effort`.

Các giá trị mặc định trong **code**:

```dotenv
VALIDATOR_MODE=hybrid
VALIDATOR_LLM_ENABLED=false
VALIDATOR_LLM_BACKEND=gemini
VALIDATOR_REVIEW_STATUSES=conditional,unknown
VALIDATOR_MAX_LLM_CALLS=20
VALIDATOR_MAX_OUTPUT_TOKENS=1024
VALIDATOR_REASONING_LEVEL=low
VALIDATOR_CACHE_ENABLED=true
VALIDATOR_CACHE_DIR=outputs/validator_cache
```

`.env`/`.env.example` có thể đã chứa override do người dùng đặt (ví dụ output 4096 và reasoning high); implementation giữ các giá trị đã có. Cache không chứa API keys. Để bật thật:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[gemini]"
.\.venv\Scripts\python.exe -m crystalball.validation --mode hybrid --enable-llm --backend gemini --out outputs/validator/figure_07_hybrid
```

**Smoke test opt-in, tối đa một API request:** cấu hình key trước, sau đó chủ động chạy:

```powershell
.\.venv\Scripts\python.exe -m crystalball.validation --mode hybrid --enable-llm --backend gemini --max-llm-calls 1 --no-cache --no-render --out outputs/validator/smoke_gemini
```

Các cạnh sau request đầu sẽ có `budget_exhausted`; kết quả offline luôn được giữ. SDK retries tắt để tránh request ẩn vượt budget. Exit code 2 báo lỗi khởi tạo/API/schema/quote recheck, sau khi đã ghi artifact offline. `--no-cache` trong smoke test bảo đảm request không được thay bằng cache hit. Tests mặc định không gọi API thật; lượt chạy live do người dùng yêu cầu được ghi riêng ở phần kết quả dưới đây.

## Thuật toán và bằng chứng

1. **Offline:** dùng `postprocess.AttackGraph` và loader `cve_dataset.load_official_cve_dataset` kiểm tra commit, SHA-256 và identity của tám CVE chính thức. H1 chỉ được tái sử dụng bảng identity hints, đã tách sang `cve_mapping.py`; không import/read `labels.json`. CVE ID rõ ràng có ưu tiên hơn hints; nhiều CVE trên một node thành mapping mơ hồ và `unknown`, không chọn cặp thuận lợi nhất. Mỗi cạnh có ID `edge-0001`, `edge-0002`, ... theo thứ tự gốc; `original_edge_id` giữ ID do generation cấp, kể cả ID trùng và cạnh song song.
2. Trích capability và prerequisite bằng các cụm quote đã khai báo trong `evidence.FACTS`, chỉ kích hoạt fact khi quote có thật trong description. Giữ riêng `possible_code_execution`, không biến “potentially” thành foothold chắc chắn. Các điều kiện product/version/access của E1 được chuyển vào module dùng chung `validation.conditions`; `experiments.env_consistency.conditions` re-export để giữ API cũ. Không dùng effect `admin` suy diễn của E1 làm bằng chứng. So sánh numeric version chuẩn hóa trailing zero, ví dụ 1.39 = 1.39.0. Quy tắc version/platform là diễn giải có ghi chú, không bảo đảm patch/backport thực tế.
3. Đánh giá bridge: thực thi code → local user; đọc file/thực thi/quyền admin → khả năng tiếp cận credentials; thực thi/admin → khả năng điều khiển audio. Hai bridge sau luôn cần bằng chứng thêm, gồm quyền process đọc hoặc sửa credential material. Generated pre/postconditions và `node.host` là claim, không xác nhận chính chúng. CVE descriptions, fact quotes, observation môi trường, inference và assumption được lưu riêng.
4. **Selective review:** chỉ `conditional,unknown` mặc định. Prompt chứa claim, source/target node, original/instance edge ID, CVE IDs, descriptions nguyên gốc, facts, thiếu hụt và Stage 1. Yêu cầu JSON schema ở `review.RESPONSE_SCHEMA`; confidence chỉ là tự đánh giá. Không tool execution, không tạo graph. `--review-controls` là opt-in rõ ràng để review mọi status; cấu hình thường cố review status khác bị từ chối.
5. **Recheck:** strict JSON (không markdown, duplicate keys, NaN hoặc field lạ); kiểm tra instance ID và CVE IDs; mọi quote phải là substring chính xác của description được cung cấp và đúng CVE. Đề xuất khác `unknown` phải dẫn cả hai endpoint. Quote chỉ xác nhận văn bản có tồn tại, chưa chứng minh entailment. LLM không nâng cạnh lên `supported`; không override hard conflicts; đề xuất negative thiếu rule xác nhận không được dùng để loại cạnh. Review có thể abstain, hạ `conditional` thành `unknown`. Disagreement, suggestion và quyết định sau recheck luôn lưu riêng.

| Status | Ý nghĩa |
| --- | --- |
| `supported` | Bridge canonical được rule xác nhận, applicability và host relationship đầy đủ |
| `conditional` | Có bridge khả dĩ nhưng prerequisite hoặc chi tiết claim chưa được xác nhận |
| `unsupported` | Capability không đủ cho một relation canonical cụ thể; không đồng nghĩa exploit bất khả thi |
| `contradicted` | Observation môi trường vi phạm prerequisite cần thiết: version/platform, host, access hoặc reachability |
| `unknown` | Thiếu/mơ hồ mapping, facts hoặc causal bridge; thiếu dữ liệu không phải bằng chứng sai |

Để tự động chứng minh toàn bộ claim, hiện chỉ nhận relation `local_execution_enables_local_exploit` cùng label chính xác `Local code execution enables local exploitation.`. Văn bản tự do có thể khẳng định thêm credentials/SYSTEM/sandbox escape nên không được nâng thành supported bằng lexical overlap. Đây là giới hạn bảo thủ có chủ đích. Không sửa label graph gốc để được rule chấp nhận.

Cache theo hash của prompt/schema/version, evidence/provenance/environment, edge instance/claim, model/backend/provider và review configuration. Mỗi cache hit vẫn được parse/recheck, không khởi tạo client hoặc tính token đã dùng trong quá khứ thành token hiện tại. Thay evidence, model, prompt hoặc reasoning sẽ invalidate cache. Lỗi cache không làm mất review. Ghi trạng thái lỗi, latency, API call count và usage gốc mỗi request; lỗi API không lưu exception message có khả năng chứa headers/key. Token total của Gemini có thể gồm thinking, nên giữ total được provider báo, không cộng prompt+completion để thay nó.

## Dữ liệu môi trường độc lập

`--environment path.json` nhận observations bên ngoài graph. File và SHA-256 được ghi provenance; toàn bộ state cũng được lưu vào report/prompt. Schema minh họa (thông tin chỉ là ví dụ, không khẳng định deployment của Figure 7):

```json
{
  "node_hosts": {"node-source-id": "host-a", "node-target-id": "host-b"},
  "hosts": {
    "host-a": {
      "platform": "raspberry_pi",
      "services": {"raspap": "2.5"},
      "services_complete": false,
      "network_access": true,
      "flags": {"attacker_has_low_priv_credential": true}
    },
    "host-b": {
      "platform": "windows",
      "services": {"oculus_desktop": "1.40.0.1"},
      "local_access": false,
      "flags": {"os_windows": true}
    }
  },
  "links": [{"from": "host-a", "to": "host-b", "reachable": false}],
  "links_complete": false
}
```

Platforms hiện hỗ trợ `raspberry_pi`, `windows`, `jetson` khi description nêu rõ. Service keys/flags xem `validation/conditions.py`; access observations: `network_access`, `local_access`, `physical_access`, `line_of_sight`. Không có service/link không suy ra vắng mặt nếu inventory chưa complete. `services_complete=true`/`links_complete=true` cho phép kết luận âm từ inventory đầy đủ. Không lấy host assignment từ chính generation. Không suy ra local access trên host B từ code execution trên host A, cũng không suy ra physical/optical access từ quyền OS.

`network_access`/`internet_exposed` mô tả truy cập từ vị trí attacker ban đầu; `links` mô tả source-host → target-host. Code execution/admin trên source có thể cung cấp vantage mới nếu link được quan sát là reachable. Link source→target bị chặn không tự chứng minh attacker ban đầu cũng không truy cập được target. Điều kiện chưa biết ở một vantage được giữ thiếu hụt thay vì suy ra false.

## Output và đánh giá A/B/C

Mỗi thư mục output gồm:

- `original_graph.json`: copy byte-exact input; `input_file.sha256` là hash byte, `graph_sha256` là hash canonical nodes/edges.
- `validated_graph.json`: mọi node/cạnh gốc với metadata status/instance ID; không thêm cạnh.
- `strict_graph.json`: chỉ cạnh `supported`; mọi cạnh bị lọc còn đầy đủ trong `validation.excluded_edges`.
- `original_graph.png/svg`, `validated_graph.png/svg`, `comparison.png/svg`: PNG 600 dpi, SVG vector, cùng `layout.json` và layout hash.
- `validation_results.json`: report chính; `offline_results.json`, `review_results.json`, `final_results.json` tách ba giai đoạn.
- `metrics.json`: A original, B offline, C hybrid trên cùng baseline. C ghi `not_run_offline_fallback` nếu chưa bật review, không được xem đó là kết quả LLM đã thực nghiệm.
- `annotation_template.json`: candidate edge IDs, claim, nodes và evidence để gán nhãn độc lập; không điền sẵn label của validator/LLM.

A giữ mọi candidate chưa validation. B/C có hai policy: retained chỉ loại `unsupported/contradicted`; strict chỉ giữ `supported`. Metric bao gồm distribution, node/edge mapping coverage (kể cả node cô lập), Unknown rate, retained fraction, validation/review wall time, additional API calls/tokens và disagreement. Thời gian A là 0 cho postprocessing bổ sung, không phải thời gian generation; thời gian không gồm render. Không dùng Success/Reliability/TotalAcquisition, flag retrieval, SCR hay Time to Exploit cho static graph.

Chưa có independent gold labels: Precision/Recall/F1 và false removals/retentions là JSON `null` (N/A). Muốn đánh giá, copy annotation template sang file khác, điền boolean `true/false` cho edge IDs được annotate (có thể xóa ID chưa gán), ghi `provenance`, giữ `independent=true`, `label_source=human` hoặc `independent_dataset`, rồi truyền `--gold path.json`. Graph hash phải khớp. Không dùng nhãn H1 sơ bộ hoặc review LLM làm gold. Recall chỉ tính trong các candidate edge được gán nhãn của original graph; không đo cạnh đúng đã bị generation bỏ sót. Người cung cấp nhãn chịu trách nhiệm tính độc lập của annotation.

Kết quả Figure 7 offline: 8/8 node mapped, 7/7 edge mapped, 6 conditional, 1 unknown, Unknown rate 1/7 = 14.29%; retained 100%, strict retained 0%; 0 API calls/tokens. Không có căn cứ kết luận graph chính xác hơn. Strict rỗng không có nghĩa mọi attack path đều sai; môi trường chưa đủ để xác nhận.

Đã chạy [hybrid live cho Figure 7, 9, 10](../outputs/validator/hybrid_run_01/README.md) theo yêu cầu người dùng: Gemini `gemini-3.8-flash`, 14/14 edge reviews qua parse/identity/quote recheck. Kết quả cuối: Figure 7 có 6 conditional + 1 unknown, Figure 9 có 3 conditional, Figure 10 có 4 conditional. Tổng 17 API calls, gồm ba retry do MAX_TOKENS; tổng provider tokens 102,964, có tính thinking và các request bị cắt. Lượt đầu dùng output 4096/reasoning high; chỉ ba cạnh lỗi được retry với output 8192 và giữ reasoning high. Không đổi `.env`. Nhãn cuối không đổi so với offline; một đề xuất unsupported được giữ unknown vì chưa đủ deterministic evidence. Baseline, original bytes/hash, edge instances và layout đều được xác nhận không đổi. Chưa có gold độc lập nên chưa kết luận độ chính xác tăng.

## Cơ sở paper và giới hạn

[Incalmo](https://arxiv.org/abs/2501.16466), PDF trong repo: §4.2 (trang 7–8), §6 (trang 10–12, tiếp §6.4 trang 13). Tái sử dụng nguyên lý structured Environment State Service tách khỏi LLM và Attack Graph Service xét host/vulnerability/reachability theo state khả dụng. Không triển khai agents, C&C hoặc execution. §6 đánh giá thực thi chiếm quyền/thu tài sản; các metric đó không chuyển sang bài toán kiểm chứng graph tĩnh. A/B/C của module là ablation hậu xử lý giữ cùng generation graph.

[Red-MIRROR](https://arxiv.org/abs/2603.27127), PDF trong repo: §3.3–3.5 (trang 5–9), §4.4 (trang 15–16). Kế thừa preservation of provenance, bounded inference và reassessment dựa trên evidence. Intra-Reflection của paper dùng kết quả thực thi để điều chỉnh action; Inter-Reflection dùng global memory/feedback và voting để cập nhật kế hoạch. Module hiện tại chỉ làm **LLM-assisted semantic edge review** và deterministic evidence recheck, không tái hiện hai execution loops, SRMM hoặc three-vote validation. Không dùng accuracy/flag success của paper để suy ra hiệu quả static validation này.

Giới hạn: rules hiện tập trung tám CVE, hints/quotes cần mở rộng thủ công cho corpus khác; version/product/access rules vẫn là diễn giải cần chuyên gia kiểm tra; chưa mô hình hóa sandbox/process boundaries chi tiết, backports, patch state hoặc độ khả thi exploit. Layout xác định có hỗ trợ cycles/self-loops/parallel edges nhưng graph rất lớn cần tùy chỉnh hình. Cache không bảo đảm model alias luôn trỏ cùng version ở provider; nên pin model ID khi làm nghiên cứu. Tính năng hybrid đã được kiểm thử bằng dependency injection/mock và chạy API Gemini thật cho ba graph C2; chưa có gold chuyên gia.

## Files và kiểm thử

Code chính: `src/crystalball/validation/{config,evidence,conditions,offline,review,pipeline,visualization,metrics,__main__}.py`, shared `cve_mapping.py`; thay đổi nhỏ tại OpenAI client, import tương thích E1/H1, `.env.example`, `.gitignore` và README. Test tại `tests/test_validator.py` cùng suite sẵn có. Unit tests dùng mock SDK/client, không gửi API thật; bao phủ disabled mode, selective status, cap, strict JSON, quoted evidence/identity, ambiguous mapping, hard conflicts, cache, immutable baseline/hash, parallel edges và metrics.

Kết quả kiểm tra ngày 2026-10-16: toàn bộ suite **202 passed**; `git diff --check` sạch; đã kiểm tra byte-exact copy/SHA-256, node set và từng edge instance trên ba graph C2. Tests cũng xác nhận hai lần render cùng input tạo PNG/SVG comparison giống nhau theo byte. Đã xem ảnh comparison và chỉnh layout/nhãn trước khi bàn giao. Các checks này xác nhận implementation và bảo toàn artifact, chưa xác nhận semantic accuracy bằng gold độc lập.

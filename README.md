# CrystalBall — Retriever-Augmented LLM Attack Graph Generation

Reproduction of: Prapty, Kundu, Iyengar — *"Using Retriever Augmented Large
Language Models for Attack Graph Generation"* (arXiv:2408.05855). Chi tiết
thuật toán (Algorithm 1/2/3) xem file PDF đính kèm trong repo; README này
chỉ tóm tắt cách chạy.

## 1. Nguồn dữ liệu

Data mẫu **không commit lên git** (chỉ commit code sinh ra nó) — chạy 1 lần
sau khi clone:
```bash
uv run python scripts/setup_sample_data.py
```
Lệnh này ghi ra `data/cve_samples/*.json` (8 CVE tái dựng từ hệ thống ví dụ
Oculus/Jetson/Raspberry Pi, Appendix A của paper) và
`data/threat_reports/*.txt` (SolarWinds + Kubernetes cluster, Appendix B/C).
Xem `scripts/setup_sample_data.py` để biết nguồn/provenance chi tiết.

**Nguồn CVE thật** (thay cho data mẫu):
- [MITRE CVE List (cvelistV5)](https://github.com/CVEProject/cvelistV5) — đúng CVE Record Format v5 mà code đang parse, chỉ cần trỏ `--input` vào thư mục đã tải.
- [NVD REST API](https://services.nvd.nist.gov/rest/json/cves/2.0) — có thêm CVSS/CPE nhưng format khác, cần viết adapter trước khi ingest.
- [cve.org](https://www.cve.org/) — tra cứu thủ công từng CVE, nút "View JSON" cho ra đúng format v5.

**Nguồn threat report thật**: bất kỳ báo cáo threat intel dạng văn bản nào
(Mandiant/FireEye, Microsoft Security blog, CISA advisories...) — lưu thành
`.txt` bất kỳ tên nào, trỏ `scripts/build_prompt.py --report` vào đó.

## 2. Ingest & embed (lưu trữ)

```bash
uv run python scripts/setup_sample_data.py                      # chỉ cần chạy 1 lần
uv run python scripts/ingest_cves.py --input data/cve_samples   # hoặc thư mục CVE của bạn
```

Thực hiện Algorithm 1: trích `ProductInfo/Platform/ProblemType` từ mô tả CVE
(heuristic mặc định, hoặc LLM thật nếu set `EXTRACTOR_BACKEND=llm`), tạo
embedding rồi lưu vào SQLite (`data/db/`) + file vector `.npy`
(`data/embeddings/`). Đổi `EMBEDDING_BACKEND=sentence-transformers` trong
`.env` để dùng đúng model `facebook/contriever-msmarco` như paper. Threat
report không cần bước này — được đọc trực tiếp khi build prompt.

## 3. Sinh prompt & xem kết quả

```bash
# Sinh prompt (chế độ CVE-context hoặc threat-report)
uv run python scripts/build_prompt.py --products "Oculus Desktop" "Jetson TX1" "Raspberry Pi"
uv run python scripts/build_prompt.py --report data/threat_reports/solarwinds_full.txt

# Dán câu trả lời của ChatGPT/Gemini vào 1 file, rồi:
uv run python scripts/ingest_response.py --response path/to/pasted_answer.txt
```

- Prompt được in ra terminal **và** lưu vào `outputs/prompts/prompt_<ts>.txt` để copy.
- Nếu set `LLM_BACKEND=openai` (hoặc `gemini`) + API key trong `.env`, `build_prompt.py` tự gọi API luôn, khỏi cần copy/paste.
- Kết quả đồ thị nằm ở `outputs/graphs/`: `graph_<ts>.json` (dữ liệu thô) + `graph_<ts>.png` (ảnh tĩnh vẽ bằng networkx/matplotlib).
- **Chưa có UI tương tác** (web/zoom/kéo node) — hiện chỉ có ảnh PNG + JSON. Nếu cần xem đẹp hơn (vd. web viewer bằng pyvis/vis.js) có thể bổ sung thêm, nói mình biết nếu muốn làm.

## 4. Đánh giá

Paper đánh giá **định tính, không có metric số**, dựa trên:
- Độ chi tiết của node/edge (paper cho rằng GPT-4 > GPT-3.5 > Bard).
- Khả năng chain lỗ hổng cross-device (precondition của node này khớp postcondition của node kia).
- Với threat report: đồ thị có tái hiện đúng các attack path mô tả trong báo cáo không (vd. 2 attack path trong vụ Kubernetes).

Repo này cung cấp đúng dữ liệu + prompt chuẩn để tự làm lại phép so sánh
đó, nhưng **không tự động chấm điểm** — việc đánh giá vẫn là xem/so sánh
thủ công các file PNG sinh ra từ các LLM khác nhau. `uv run pytest` chỉ
kiểm tra tính đúng của pipeline (DB, retriever, parser), không đánh giá
"chất lượng" attack graph.

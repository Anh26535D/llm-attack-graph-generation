# C2: grounded / self-refine / debate

Cùng graph nháp; validation offline không gọi LLM. Chưa có gold độc lập: accuracy = N/A.

| Round | Cách sinh | Trạng thái | Cạnh | Nhãn offline | Calls (gồm draft chung) |
|---|---|---|---:|---|---:|
| 1 | grounded | ready_for_independent_validation | 2 | {'conditional': 2} | 1 |
| 1 | self_refine | ready_for_independent_validation | 2 | {'conditional': 2} | 4 |
| 1 | debate | ready_for_independent_validation | 2 | {'conditional': 2} | 4 |

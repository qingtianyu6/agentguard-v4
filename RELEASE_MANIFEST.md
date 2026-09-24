# AgentGuard V3.0 Release Manifest

## Release Identity

- Version: `3.0.0-national-research`
- Build type: National Competition Research Build
- Default database: SQLite (`backend/agentguard.db`)
- API compatibility: original 113 HTTP operations preserved
- V3 HTTP operations: 131
- Backend verification: 15 tests passed
- Frontend verification: TypeScript source static type-check passed with temporary local declaration stubs; npm package installation could not complete in the isolated build environment because registry access timed out.

## Clean Seed Database

| Table | Count |
|---|---:|
| Agents | 3 |
| Policies | 3 |
| Contracts | 3 |
| Tools | 7 |
| Benchmarks | 1 |
| Experiments | 2 |
| Actions | 0 |
| Decisions | 0 |
| Risks | 0 |
| Recoveries | 0 |
| Audit Events | 0 |

## Runtime Frozen Test Regression

These values are produced by the current local candidate test split and are **software regression evidence, not an external real-world safety claim**.

| Mode | Policy Fidelity | ASR | FPR | Benign Completion | Recovery | Overhead |
|---|---:|---:|---:|---:|---:|---:|
| No Guard | 0.50 | 1.00 | 0.00 | 1.00 | 0.00 | 0.0 ms |
| Single-Step | 0.85 | 0.20 | 0.10 | 0.90 | 1.00 | 3.8 ms |
| Full Trajectory | 1.00 | 0.00 | 0.00 | 1.00 | 1.00 | 7.2 ms |

## Compiler Ablation — Candidate Test Split

| Mode | Semantic Accuracy | Critical Recall | Graph Validity | Formal Pass |
|---|---:|---:|---:|---:|
| Direct DSL | 0.7143 | 0.76 | 0.00 | 0.00 |
| Structured | 0.9714 | 0.96 | 0.00 | 0.00 |
| Graph IR | 0.9714 | 0.96 | 1.00 | 0.00 |
| P2C-V Full | 0.9714 | 0.96 | 1.00 | 1.00 |

## Dataset Status

- Runtime Scenario Candidate: 100
- Policy Compilation Candidate: 50
- Runtime split: 60 train / 20 dev / 20 test
- Threat categories: 8
- `ground_truth_status`: `candidate_labels_pending_human_review`

The labels must receive team human review/adjudication before being described in a paper or competition material as human Ground Truth.

## Key File SHA-256

| File | Bytes | SHA-256 |
|---|---:|---|
| `backend/app/main.py` | 55298 | `e0867e83c61f47db6dec3b4a2466c60e590996734e0989864c6ba03f691e683b` |
| `backend/app/services/p2cv_v3.py` | 3612 | `86147c0637b7f9390a37dd0f87e2b0ec5387fac89801d7d6421fa20bc5d06940` |
| `backend/app/services/formal_verifier.py` | 10738 | `69fd2366287a07a90101095732ae440a30839001870b9cef255dd0e5195bc2bc` |
| `backend/app/services/runtime_guard.py` | 12821 | `a4eb51f1d8b3c759b68fcfeaa832675d217e9e0ae9a8ebfdd0fc454d7fe41131` |
| `benchmark/scenarios/agentguard_bench_v3_100.json` | 81542 | `f1ae3d4fdec8395304f769fe4fcf66ec5108c08c65e4412bba114edbf98177e8` |
| `benchmark/policies/policy_ground_truth_v3_50.json` | 18247 | `6286c6c781f599c7ecf82dba206ea5c08a2296b9d19df9f60bd199a65f49828d` |
| `benchmark/manifests/v3_manifest.json` | 875 | `8aa5efd9271469a9d7026a391c26fe143343523aaa35d58378c998dff28e7fab` |
| `frontend/src/pages/PolicyStudio.tsx` | 8859 | `1245e0bc0ced33cb73b8730ad7a080feeea68c320d574ee022b8099f227308a0` |
| `frontend/src/pages/AttackLab.tsx` | 6341 | `ebbbbc8292103d20620a8d311ce3b3741d79182c5e34f45f35ec0dd9b2c1460f` |
| `docs/02_protocol/openapi-v3.json` | 117317 | `0b607ae02a6fbfc6d2e5911172c8cee03a84894cbd717e5553c9aadca3c6389f` |

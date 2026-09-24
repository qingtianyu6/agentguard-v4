# Experiments

V3 正式实验输出统一写入：

```text
experiments/results/<run_id>/
  config.json
  raw.jsonl
  metrics.json
  summary.md
```

推荐固定 seed=42，并在最终 Test Set 冻结后禁止用测试结果继续调参。

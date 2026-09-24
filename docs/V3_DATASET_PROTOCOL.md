# AgentGuard-Bench V3 数据集协议

## 当前状态

V3 代码包中的 100 Runtime Scenario 与 50 Policy Compilation Case 是**候选标注集**，用于研发回归、接口验证和实验框架联调。

它们尚不能在论文中直接宣称为“100 条人工 Ground Truth”。

## 正式 Ground Truth 升级流程

每条 Scenario 至少由两名标注者独立判断：

- expected decision
- risk type
- whether approval is required
- allowed safe alternative
- evidence span / policy basis

冲突进入第三人复核。

建议保存：

```text
annotator_a.jsonl
annotator_b.jsonl
adjudicated.jsonl
agreement.json
```

至少计算：

- Decision agreement
- Risk type agreement
- Cohen's kappa（适用于分类标签）

只有完成该流程后，manifest 中 `ground_truth_status` 才能从：

```text
candidate_labels_pending_human_review
```

升级为：

```text
human_adjudicated_ground_truth
```

## Split

V3 当前固定：

- Train: 60
- Dev: 20
- Test: 20

正式竞赛冻结后 Test Set 不允许继续用于调参。

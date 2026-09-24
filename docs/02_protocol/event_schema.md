# 事件模式 v1

以 `shared/schemas/event.py` 为唯一规范。状态顺序为 proposed → decided → committed → completed/failed。denied、未审批和未知工具仅可 aborted；只把 completed 且可信的事件用于时序前置条件。每个决策记录工具指纹、契约版本及环境快照，重试使用同一幂等键。历史回放必须复用当时的策略版本；无法获取则标记不能复算。

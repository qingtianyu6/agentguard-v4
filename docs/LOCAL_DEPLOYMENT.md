# 本机部署（受控演示）

从项目根目录运行：

```bash
python -m pip install -r backend/requirements.txt
cd frontend && npm ci && npm run build && cd ..
python scripts/deploy_local.py start
python scripts/deploy_local.py status
```

页面在 `http://127.0.0.1:5173`，接口在 `http://127.0.0.1:8000`。两者仅监听当前机器的 `127.0.0.1`。数据和日志写入 `runtime/local/`；停止运行 `python scripts/deploy_local.py stop`。关闭或重建当前运行环境后需重新启动。

此脚本强制使用 `sandbox` 配置及单机 SQLite，仅用于演示。不要将该服务通过端口转发或反向代理对外开放。生产环境需要独立数据库和服务身份、TLS、网络隔离、持久化存储及实际 ToolHive 部署与端到端验证；当前代码包尚未满足 V4 设计书的全部验收条件。

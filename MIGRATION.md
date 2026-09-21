# Migration

当前发布面只有 CONNECT-IP。保留现有 P-256 `server.crt`、`server.key` 和
stateless reset key；配置使用 `configs/connect-ip.example.yaml`，并在启用
systemd 前运行 `check-config`、`doctor` 和 network prepare。

旧 CONNECT-UDP/TCP 配置、服务单元、TUN offload/GRO 和 qlog 配置不再受支持，
应从部署清单中移除。

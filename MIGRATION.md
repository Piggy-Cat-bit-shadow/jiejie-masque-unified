# Migration

当前发布面只有 CONNECT-IP。保留现有 P-256 `server.crt`、`server.key`；配置使用
`configs/connect-ip.example.yaml`。启用 systemd
前由部署系统完成转发、NAT 和 TUN 网络配置，并可人工运行 `check-config`。

旧 CONNECT-UDP/TCP 配置、服务单元、TUN offload/GRO 和 qlog 配置不再受支持，
应从部署清单中移除。

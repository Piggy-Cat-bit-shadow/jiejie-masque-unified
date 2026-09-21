# Operations

本服务只提供 CONNECT-IP。配置入口是 `configs/connect-ip.example.yaml`；旧的
CONNECT-UDP/TCP、TUN offload/GRO、qlog、session idle timeout 和 host-network
check interval 配置均已删除，未知字段会被拒绝。

启动前执行：

```bash
jiejie-masque check-config --config /etc/jiejie-masque/connect-ip.yaml
jiejie-masque doctor --config /etc/jiejie-masque/connect-ip.yaml
```

systemd 单元只在启动阶段执行 network prepare 和数据面检查，随后发送
`READY=1`。服务没有 watchdog heartbeat；systemd 的停止超时为 5 秒。

每 30 秒输出一行 identity-free aggregate telemetry，同时保留 lifetime
counter。使用 `--version --verbose` 或启动日志确认 main、connect-ip-go 和
quic-go provenance。生产默认 congestion controller 是 CUBIC；BBR 和其他
传输实验不得通过配置缺省自动启用。

IPv4 NAT、IPv6 forwarding/egress、TUN 地址和 DNS gateway 必须在部署环境中
由 `doctor` 与 network prepare 验证。DNS gateway 只监听 tunnel 地址。

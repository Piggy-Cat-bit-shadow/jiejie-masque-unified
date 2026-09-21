# jiejie-masque

面向 Linux 的精简 CONNECT-IP MASQUE 服务端。当前产品面只包含经过验证的
CONNECT-IP：P-256 客户端认证、IPv4/IPv6/dual-stack tunnel、Mihomo 配置生成、
CUBIC/实验性 BBR 控制器，以及 QUIC 外层 UDP GSO。

## 运行面

- TUN 数据面固定使用 1280 MTU、普通读写和有界 packet pool；不启用 TUN
  VNET_HDR、TUN GSO 或 TX GRO。
- QUIC 的 DATAGRAM backpressure、pacing 和外层 UDP GSO 仍由维护 fork 提供。
- 服务只在启动时执行 forwarding、TUN、NAT 和 IPv6 egress 检查；不运行后台
  host-network supervisor、应用层 idle reaper 或 systemd watchdog heartbeat。
- 日志保持 identity-free，每 30 秒输出一行 aggregate 数据面速率和 QUIC 状态。
- DNS gateway 是 CONNECT-IP 的本地辅助功能，只绑定 tunnel 地址，不对公网开放。

## 构建与配置

```bash
go build ./cmd/jiejie-masque
./jiejie-masque check-config --config configs/connect-ip.example.yaml
./jiejie-masque doctor --config configs/connect-ip.example.yaml
./jiejie-masque serve --config /etc/jiejie-masque/connect-ip.yaml
```

保留的命令是 `serve`、`check-config`、`doctor`、`mihomo-config`、`keygen`、
`server-keygen` 和 `version`。network prepare helper 通过
`network-prepare-info` 读取配置，避免 shell 解析 YAML。

主项目依赖固定到维护 fork 的 pseudo-version；生产默认 congestion controller
仍是 CUBIC。任何 BBR、PMTU 或其他传输实验都必须独立 benchmark，并且不会因
默认配置缺省而自动启用。

systemd 单元位于 `contrib/jiejie-masque-connect-ip.service`，启动顺序是
`check-config`、network prepare、服务本身；停止超时为 5 秒。

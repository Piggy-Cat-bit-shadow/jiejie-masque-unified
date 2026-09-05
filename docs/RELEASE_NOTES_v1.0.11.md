# jiejie-masque v1.0.11

## 主要修复

F-701 — CONNECT-IP active-UFW integration。

此前 CONNECT-IP 的 QUIC、TLS 和 session 可以正常建立，但 active UFW 可能
阻断 TUN 的 `INPUT` / `FORWARD` 数据路径，导致客户端 DNS、网页或测速
timeout。

v1.0.11 的 network prepare：

- 自动配置 tunnel-local DNS 的 UDP/TCP `INPUT` allow。
- 自动配置 TUN → WAN 的 `FORWARD` allow。
- 保留既有 NAT/MASQUERADE 与 `net.ipv4.ip_forward=1`。
- 对目标规则进行幂等检测，并安全清理项目专属 stale rules。
- 新规则添加失败时保留旧规则；不修改用户已有 UFW 规则。
- UFW inactive/missing 不修改；custom firewall 仍需管理员手工集成。

## 安全边界

- 不修改 global `INPUT` / `FORWARD` policy。
- 不 blanket allow TUN。
- 不关闭 UFW。
- 不声称自动兼容所有 firewall 实现。

## 未改变

- CONNECT-IP core dataplane unchanged。
- CONNECT-UDP unchanged。
- CONNECT-TCP unchanged。
- dependency forks unchanged。
- dataplane invariants and frozen ownership/queue behavior unchanged。

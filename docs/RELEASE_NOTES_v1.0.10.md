# jiejie-masque v1.0.10

> F-601 correctness maintenance 与中文用户文档 release。

## 修复

- 修复 Linux 可选 TCP TX GRO 路径跨越 TCP PSH boundary 继续聚合的问题。
- 带 PSH 的 segment 可以作为当前 GRO aggregate 的最后一个 segment；后续 segment
  不会再被合入该 aggregate。
- 保留 `ACK + ACK|PSH` 的合法聚合、final PSH 的合法行为，以及 initial PSH 的独立边界。
- 增加 IPv4、IPv6、multiple PSH 和真实 `WriteBatch` 输出回归测试。

## 文档

- README 改为中文为主，并增加架构概览、快速开始、客户端配置、运维、安全和故障排查入口。
- `docs/OPERATIONS.md` 重构为中文 Linux 安装与运维手册。
- 新增 `CHANGELOG.md` 中文版本演进摘要。

## 兼容性与边界

- `tun_tx_gro` 默认仍为 `false`；默认生产路径此前不受该 optional feature 影响。
- CONNECT-IP、CONNECT-UDP、CONNECT-TCP、DNS gateway、Session NAT、QUIC、queue、PacketPool
  和 release provenance architecture 没有重新设计。
- F-404 仍为 `REPRODUCTION REQUIRED / NON-RELEASE-BLOCKING`。

v1.0.10 已通过正式 tag workflow 与 same-artifact release 验证；本次 release 不包含 production deployment。

# jiejie-masque v1.0.14

v1.0.14 收口已验证的 userspace dataplane efficiency work 与维护/正确性
候选。它不是新的 transport architecture，也不改变 QUIC congestion、MTU、TUN
offload/GRO、DATAGRAM queue 或 retained-RX 默认值。

## Dataplane efficiency

- CONNECT-UDP 在 Linux 上使用有界 `recvmmsg` 读取 target→client 流量，并对
  ready client→target 流量使用有界 ready-drain / `sendmmsg`；buffer ownership
  与 release 语义保持不变。
- CONNECT-IP session writer 使用 block-first 与有界 ready FIFO drain，配合
  capability caching、burst bookkeeping / `Touch` 和 dequeue-statistics 的
  降开销处理。每个 packet 仍通过下层 `WritePacketBufferOwned` 发送；没有引入
  跨 fork batch API。
- 这些改动是 userspace batching、bookkeeping 与 syscall efficiency 改进；没有
  扩大 QUIC DATAGRAM queue，也没有移除最终 serialization copy。

## Maintenance and correctness

- 新增只读 `jiejie-masque doctor --config ...`，检查 host config、IPv4
  forwarding、TUN、external interface、NAT、active UFW 规则与 reset key，且不
  修改 host state。
- H-307：修复 CONNECT-UDP request stream 在 `TrackStream` 前到达的 early
  DATAGRAM race。每个未跟踪 stream 最多保留一个、每 H3 connection 最多 32 个、
  生命周期最多一秒；duplicate early datagram 会释放，`TrackStream` 原子 claim，
  connection close 释放 retained entries。
- F-404：cleanup genuine failure 的 shadow IP 在当前进程生命周期内 quarantine；
  `CleanupStats.Quarantined` 提供可观测计数，cleanup executor shutdown 未执行的
  job 同样会 quarantine。
- 增加 Linux network-namespace/veth/nft/conntrack lifecycle reproducer，以及
  future Git metadata privacy gate。

## Field observation, not a general benchmark

一次跨境高 RTT 生产链路 A/B 观察到：Reno/default 与 Session outbound queue 256
时，Mihomo CONNECT-IP 手机 Fast.com 约为 33 Mbps，并出现大量 CONNECT-IP
outbound queue overflow。切换为 CUBIC 且将该部署的 outbound queue 调至 1024 后，
观察到约 45 Mbps（约 36%）；CUBIC 但仍为 256 时再次出现严重 overflow，一次日志
记录 `aggregate_drops=1403`。

该环境的主要吞吐闸门之一是 QUIC congestion-control / pacing / backpressure 与
CONNECT-IP Session outbound burst buffering 的组合：发送侧积压、inner IP packet
主动丢弃、内层 TCP 重传/窗口收缩会形成反馈链。此观察不构成通用性能保证，也没有
在本 release 中改变任何用户的 congestion default、outbound queue default、MTU 或
TUN/queue 默认行为。

## Validation boundaries

- F-302 harness 是 partial kernel-state reproducer，不是完整 daemon-restart
  proof；privileged Linux validation 仍待执行。
- privileged Linux F-404 harness、真实 Surge E2E、真实 production UFW-host
  doctor 和广泛 WAN/client E2E 不在 release automation 中。
- production 未由本 release 自动部署。

## Dependency provenance

```text
quic-go:      509e22e92ae01477de7088738910f77da2631897
  pseudo:     v0.61.1-0.20260906101854-509e22e92ae0
connect-ip:   e645a82498ea70e3411b99e7a338ac740629abdd
  pseudo:     v0.0.0-20260906041020-e645a82498ea
```

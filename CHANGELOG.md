# 更新日志

本文是面向用户的中文版本演进摘要。历史 `docs/RELEASE_NOTES_*.md` 文件属于
release provenance，不在这里覆盖重写。

## Unreleased

- CONNECT-IP 默认使用 native CUBIC，Session outbound queue 默认调整为 1024。
- 当前使用的 quic-go fork 将 bounded QUIC DATAGRAM queue 调整为 512/256，
  HTTP/3 stream DATAGRAM queue 调整为 256。
- 保持 MTU 1280、TUN offload/TX-GRO 默认关闭，不引入未经 WAN 验证的 BBR。

## v1.0.14

这是一次已验证 userspace dataplane efficiency 与 maintenance/correctness
closure release；不改变 congestion、MTU、TUN/GRO、DATAGRAM queue 或 retained-RX
默认值。

- CONNECT-UDP 增加 Linux 有界 `recvmmsg` target→client 读取与 ready-drain /
  `sendmmsg` client→target 发送，保留 ownership、release 与最终 serialization
  copy 边界。
- CONNECT-IP session writer 增加 block-first、有界 ready FIFO drain、capability
  caching 与低开销 burst bookkeeping；仍逐 packet 调用下层
  `WritePacketBufferOwned`。
- 新增严格只读的 CONNECT-IP `doctor`，以及 H-307 early DATAGRAM race 修复：
  每 stream 一个、每 connection 32 个、最多一秒、duplicate release、atomic
  `TrackStream` claim 与 close cleanup。
- F-404 cleanup failure shadow-IP process-lifetime quarantine 与统计、Linux
  conntrack lifecycle harness、future Git metadata privacy gate 已纳入。

特定跨境高 RTT 生产链路的 field observation 显示：CUBIC 加更充足的 Session
outbound burst buffer 可缓解 Reno/default + 256 深度下的 overflow feedback loop；
这不是通用 benchmark 或默认配置变更。F-302 harness 仍是 partial kernel-state
reproducer，真实 privileged Linux/Surge/production-host validation 未在 release
automation 中完成。

## v1.0.13

这是一次 dependency / upstream synchronization 与 migration correctness
closure release，不是性能重写或新的传输架构。

- QUIC foundation 同步到 canonical quic-go 0.62 generation；CONNECT-IP
  同步到 0.62-compatible generation。
- Go toolchain 更新到 1.26.8，YAML module 迁移到 `go.yaml.in/yaml/v3 v3.0.5`。
- GitHub Actions refresh 继续使用完整 SHA pin，并完成 dependency-fork CI
  validation closure。
- 保持现有 owned DATAGRAM、retained RX、PacketBuffer、bounded queue 与
  final serialization architecture。
- 关闭 F-901 至 F-908 migration findings：TX-GRO capability gate、IPv4
  full-IHL checksum、prepared-DATAGRAM fallback、terminal close normalization、
  clean-clone provenance、fork CI attribution、owned DATAGRAM discard release
  以及 plain CONNECT-IP packet API normalization。
- QUIC/HTTP3 DATAGRAM、CONNECT-IP、CONNECT-UDP、CONNECT-TCP、Session NAT、DNS
  Gateway、UFW/network-prepare 与 congestion defaults 的既有行为保持不变。

Real Mihomo 与 Surge client E2E 未在本次 release-validation environment
执行；early-DATAGRAM pre-track behavior 仍是 test/compatibility gap，未确认
为 runtime defect。生产未部署。

## v1.0.12

- F-803 串行化共享 TX-GRO scratch buffer，并增加并发 `WriteBatch` 回归测试。
- F-804 校验完整 IPv4 fragment field，同时保留仅设置 DF 的正常报文。
- F-805 仅对 ICMP error 类型解析 quoted IPv4，informational payload 保持不透明。
- F-806 对分片 ICMP 只转换外层地址并重算外层校验和，保留 payload 与 ICMP 校验和。
- CI 对齐仓库默认分支、固定官方 Actions 完整 SHA，并校验当前依赖 provenance。

这是 maintenance / correctness release；默认 `tun_tx_gro=false` 的生产路径保持不变。

- F-807 对齐 CONNECT-IP stateless reset key 默认路径与 packaged systemd
  `StateDirectory`。
- F-808 将 F-701 network-prepare fake-command regression 纳入正式 build/tag gate。
- F-809 拒绝与 runtime 固定 `masque0` 不一致的 TUN interface override。
- DNS 分片 contract 明确为 MTU-safe UDP、EDNS 约 1232 bytes 与 TCP fallback；不实现
  fragment tracker。
- F-810 修复可选 TCP TX-GRO 的 segment-size ordering：首段确定 `gso_size`，最后一段
  可为 short segment，但 short 后不再继续聚合更大 segment。
- F-801～F-810 均已在本版本 release candidate 中验证并发布；核心 QUIC/H3、
  CONNECT-UDP、CONNECT-TCP、ownership model、retained RX model、final serialization
  copy、dependency pins 与 congestion control 未改变。
- N-06、N-09 继续 deferred；本版本不包含 DNS fragment tracker 或 runtime UFW supervisor。
- v1.0.12 已通过 annotated tag workflow 正式发布；CI artifact 与 GitHub Release asset
  已完成大小、SHA256 与 byte-for-byte 校验。

## v1.0.11

### 修复

- F-701：修复 active UFW 环境下 CONNECT-IP network prepare 未自动放行 TUN
  `INPUT` / `FORWARD` 的 deployment correctness bug。
- active UFW 自动配置 tunnel-local DNS 的 UDP/TCP `INPUT` 与 TUN→WAN
  `FORWARD`，并保留 NAT/MASQUERADE 与 IPv4 forwarding。
- UFW 规则具备幂等检测，仅清理项目专属 stale rules；UFW inactive/missing
  不修改，custom firewall 仍由管理员自行集成。

### 运维

- 修复 `session established` 但 TUN 数据面被 UFW 阻断导致网页、测速或 DNS
  timeout 的部署问题。
- 这不是 protocol performance improvement，也不声称兼容所有 firewall 实现。

### 发布 provenance

- v1.0.11 已由 annotated tag workflow 正式发布；CI artifact 与 GitHub
  Release asset 已完成大小、SHA256 与 byte-for-byte 校验。
- F-701：FIXED / RELEASED v1.0.11；production 未部署。

## v1.0.10

### 修复

- 修复 Linux TCP TX GRO 在吸收带 PSH 的 segment 后继续跨越 PSH 边界聚合的问题。
- 保留 final PSH 的合法聚合行为，同时阻止后续 TCP segment 被错误合入同一 group。
- 增加 IPv4、IPv6、initial/final/intermediate/multiple PSH 的真实 `WriteBatch` 回归覆盖。

### 文档

- README 改为中文为主，并把深度技术说明放入可展开区。
- 新增中文安装、配置、systemd、DNS、升级、回滚和故障排查手册。
- 新增中文版本演进摘要与 v1.0.10 release notes。
- 完善 CONNECT-IP 故障排查，明确 `session established` 后网页/测速失败优先检查 `FORWARD`，tunnel DNS 失败优先检查 `INPUT`。

v1.0.10 已正式发布，但未部署 production。

## v1.0.9

- 修复 conntrack cleanup 结果分类与超时判断。
- 正式 release 使用 annotated tag、CI 单次构建和 same-artifact 发布验证。
- 发布流程的 tag provenance、artifact checksum、Release digest 和 byte comparison 已闭合。

## v1.0.8

- 正式发布 CONNECT-IP/CONNECT-UDP 服务端维护基线，并保留同一 artifact 的发布验证记录。
- 继续维护 bounded queue、ownership、DNS gateway、TargetPolicy 和 systemd 生命周期约束。

## v1.0.3

- 完成第三轮维护审计中的协议、兼容性、DNS-over-TCP、认证 identity 和 release metadata 修复。
- 历史 release asset 的 provenance gap 已在后续 release workflow 中关闭；历史 tag 与 asset 不变。

## v1.0.2

- 完成 Mihomo key encoding、DNS/config/privacy、TargetPolicy 和 Session-NAT bounded cleanup 维护批次。
- 冻结核心数据面 ownership、queue、buffer 和最终 serialization copy 边界。

## v1.0.1

- 完成初始统一 MASQUE 服务端的兼容性、配置和运维维护。

## v1.0.0

- 首个统一 MASQUE 服务端基线版本。

## v1.0.4–v1.0.7

这些版本属于 release-pipeline hardening 阶段的历史 tag-only failed release attempts，
没有成为正式 canonical release；历史 tag 保持 immutable。

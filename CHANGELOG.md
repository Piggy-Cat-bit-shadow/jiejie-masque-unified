# 更新日志

本文是面向用户的中文版本演进摘要。历史 `docs/RELEASE_NOTES_*.md` 文件属于
release provenance，不在这里覆盖重写。

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

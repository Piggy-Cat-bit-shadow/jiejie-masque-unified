# 更新日志

本文是面向用户的中文版本演进摘要。历史 `docs/RELEASE_NOTES_*.md` 文件属于
release provenance，不在这里覆盖重写。

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

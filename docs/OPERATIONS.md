# jiejie-masque 中文运维手册

本文面向第一次部署 jiejie-masque 的 Linux 运维人员。命令、配置字段和
systemd unit 以仓库当前代码与 `configs/*.example.yaml` 为准；不要从旧博客
复制已经废弃的字段。

## 1. 适用范围与运行模式

jiejie-masque 有两个独立运行模式：

- `connect-ip`：Linux TUN、P-256 client authentication、Session NAT、tunnel-local DNS。
- `connect-udp`：RFC 9298 CONNECT-UDP、HTTP/3 DATAGRAM、UDP relay，以及同一服务中的 CONNECT-TCP stream relay。

CONNECT-IP 需要 `CAP_NET_ADMIN` 与 network prepare；CONNECT-UDP 不需要
`CAP_NET_ADMIN`，也不应获得该 capability。

## 2. 安装

从 GitHub Releases 下载 Linux amd64 binary，核对 SHA256 后安装：

```sh
chmod +x jiejie-masque-linux-amd64
sudo install -m 755 jiejie-masque-linux-amd64 /usr/local/bin/jiejie-masque
sudo install -d -m 700 /etc/jiejie-masque
```

复制对应 example：

```sh
sudo install -m 600 configs/connect-ip.example.yaml /etc/jiejie-masque/connect-ip.yaml
sudo install -m 600 configs/connect-udp.example.yaml /etc/jiejie-masque/connect-udp.yaml
```

服务配置和 EnvironmentFile 只允许 service user 或 root 读取：

```sh
sudo chmod 600 /etc/jiejie-masque/*.yaml /etc/jiejie-masque/*.env 2>/dev/null || true
```

## 3. 生成 server 与 client key

生成 CONNECT-IP server certificate/private key：

```sh
sudo install -d -m 700 /etc/jiejie-masque/connect-ip
jiejie-masque server-keygen \
  --cert /etc/jiejie-masque/connect-ip/server.crt \
  --key /etc/jiejie-masque/connect-ip/server.key
sudo chmod 600 /etc/jiejie-masque/connect-ip/server.key
```

生成 client P-256 key：

```sh
jiejie-masque keygen
```

把输出的 client public key 放进 `client.public_keys` 或命名的 `clients` 条目，
把 private key 安全保存给客户端。不要把真实 private key 写进 README、YAML
或公开 issue。

## 4. CONNECT-IP

从 `configs/connect-ip.example.yaml` 开始。必须核对：

- `listen`、TLS certificate/key 和 QUIC stateless reset key path。
- `server.tunnel_ipv4`、`server.mtu` 与 client tunnel address。
- `host_network.external_interface`；留空时程序根据 default route 自动检测。
- `server.session_nat` 的 pool 必须位于 server network 内，且不能包含 server tunnel address。
- `dns_gateway.upstream` 默认是 `127.0.0.1:53`，gateway 只绑定 tunnel address。

示例默认保持 `tun_offload: false`、`tun_tx_gro: false`。如果开启 TX GRO，
必须同时开启 `tun_offload`，并先在 Linux 环境验证。v1.0.10 修复了 TCP TX GRO
的 PSH boundary correctness，但默认 offload 行为没有改变。

检查配置：

```sh
jiejie-masque check-config --config /etc/jiejie-masque/connect-ip.yaml
```

### network prepare

CONNECT-IP network prepare helper 的 external interface 优先级是：

```text
CLI --interface > MASQUE_EXTERNAL_INTERFACE > YAML host_network.external_interface > default-route auto-detect
```

helper 通过 binary 的 `network-prepare-info` 获取 tunnel prefix/interface，不自行
解析 YAML。手工运行前确认 `nft`、`/proc/sys/net/ipv4/ip_forward` 和目标 interface：

```sh
sudo /usr/local/libexec/jiejie-masque-connect-ip-network-prepare \
  --config /etc/jiejie-masque/connect-ip.yaml
```

## 5. CONNECT-UDP 与 CONNECT-TCP

从 `configs/connect-udp.example.yaml` 开始：

- `public_authority` 必须是客户端实际使用的 authority。
- `tls.cert` / `tls.key` 必须存在并匹配。
- 使用 `auth.users` 与 `password_env`，不要把 password 直接写入 YAML。
- `target_policy.allow_private` 默认 `false`，只允许 globally reachable unicast。
- `limits.max_active_flows` 默认 256，单用户默认 64，idle timeout 默认 1h。

公网服务保持：

```yaml
auth:
  allow_unauthenticated: false
```

CONNECT-TCP 与 CONNECT-UDP 共用 HTTP/3 listener、认证和 TargetPolicy。client
request EOF 会转为 target `CloseWrite`，response 方向继续工作，保留 TCP
half-close 语义。

检查配置：

```sh
jiejie-masque check-config --config /etc/jiejie-masque/connect-udp.yaml
```

## 6. Mihomo 配置生成

```sh
jiejie-masque mihomo-config \
  --config /etc/jiejie-masque/connect-ip.yaml \
  --server vpn.example.com \
  --port 443 \
  --private-key BASE64_CLIENT_PRIVATE_KEY \
  --name MASQUE
```

生成器会根据 server certificate 导出 endpoint public key，并在 DNS gateway
启用时生成 `remote-dns-resolve` 与 `udp://<tunnel-gateway>:5353`。

密钥格式必须区分：

| 用途 | 格式 |
| --- | --- |
| client `private-key` | SEC1 EC DER Base64 |
| server endpoint `public-key` | PKIX / SubjectPublicKeyInfo DER Base64 |
| client authentication `public_key` | raw uncompressed P-256 point Base64 |

不要把这三种 Base64 互换。Mihomo 的 inner MIPS/`bbr3` 和 outer `bbr` 是生成器
当前输出的一部分；不同网络路径的表现应自行 A/B，不代表本项目对所有链路的性能承诺。

## 7. DNS gateway

CONNECT-IP DNS gateway 同时提供 UDP 与 TCP，监听 server tunnel address 的
5353 端口，向本机 `127.0.0.1:53` 转发。UDP request 最大 4096 bytes；DNS-over-TCP
保持 downstream connection，可处理 sequential 和 pipelined length-prefixed query，
并按顺序返回结果。它不会监听公网地址，也不会回退到公共 DNS resolver。

部署前确认本机 resolver（例如 AdGuard Home）确实监听 `127.0.0.1:53`：

```sh
ss -Hlunpt | grep ':53'
```

## 8. CONNECT-IP Linux 防火墙与 UFW

CONNECT-IP 的 QUIC handshake 成功，不代表 TUN 注入后的 IP packet 已经通过主机
firewall。排查时区分两条路径：

- **Tunnel-local DNS**：`client → TUN (masque0) → tunnel gateway:5353`。目标是本机 tunnel address，进入 `INPUT`。
- **普通 Internet 转发**：`client tunnel IP → TUN → routing → WAN interface`。目标在外部网络，进入 `FORWARD`。

这也解释了一个常见状态：QUIC 正常、session established、TUN RX 增长，但 TUN TX
不增长，随后客户端网页、测速或 DNS timeout。此时除了检查 `ip_forward=1`、NAT/
MASQUERADE 和 route，还要检查 UFW/nftables/iptables 是否拒绝了 TUN 的 `INPUT` 或
`FORWARD`。

先确认实际 interface、网段和 UFW 状态；下面的 `masque0`、`eth0`、`10.200.0.0/16`
只是与 example 对应的示例，必须替换成实际值：

```sh
sudo ufw status verbose
ip addr show masque0
ip route
sudo nft list ruleset
```

使用 UFW 时，DNS 是发往本机 tunnel gateway 的 `INPUT` 流量，普通 Internet 是
经由 WAN interface 的 `FORWARD` 流量。可以按最小范围增加规则：

```sh
# Tunnel-local DNS；按实际 gateway address、interface 和 TCP/UDP 需求调整。
sudo ufw allow in on masque0 to 10.200.0.1 port 5353 proto udp
sudo ufw allow in on masque0 to 10.200.0.1 port 5353 proto tcp

# Client packet 从 TUN 转发到 WAN；替换 interface 与 tunnel subnet。
sudo ufw route allow in on masque0 out on eth0 from 10.200.0.0/16
sudo ufw reload
sudo ufw status verbose
```

不要为了绕过问题把全局 `INPUT` 或 `FORWARD` policy 改成无条件 `ACCEPT`。规则应
限制在实际 TUN interface、tunnel subnet、WAN interface 和 DNS gateway port。
UFW 规则通过后仍需确认 network prepare 写入的 NAT/MASQUERADE 规则存在；firewall
放行不能替代 NAT，NAT 也不能替代 `FORWARD` 放行。

日志排查可暂时提高 UFW logging，再复现一次后恢复合适级别：

```sh
sudo ufw logging medium
sudo journalctl -k -n 200 --no-pager
sudo nft list ruleset
```

## 9. systemd

仓库提供两个 unit：

- `jiejie-masque-connect-ip.service`：`User=masque-lite`，拥有 `CAP_NET_ADMIN`，执行 network prepare。
- `jiejie-masque-connect-udp.service`：`User=masque`，无 `CAP_NET_ADMIN`。

安装、检查并启动：

```sh
sudo install -m 644 contrib/jiejie-masque-connect-ip.service /etc/systemd/system/
sudo install -m 644 contrib/jiejie-masque-connect-udp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now jiejie-masque-connect-ip.service
sudo systemctl status jiejie-masque-connect-ip.service
```

按实际启用的 mode 选择一个 service，不要同时让两个 service 争用同一 listener。
unit 使用 `Type=notify`、`WatchdogSec=30s` 和 graceful shutdown。watchdog 只证明
进程能调度并发送 heartbeat，不等于 QUIC event loop、数据面或公网可达性正常；
host-network deep probe 是另一套 30 秒检查，连续两次失败才会变成 fatal。

## 10. 健康检查与诊断

```sh
sudo journalctl -u jiejie-masque-connect-ip.service -n 200 --no-pager
sudo systemctl show jiejie-masque-connect-ip.service -p MemoryCurrent -p MemoryPeak -p TasksCurrent
sudo ss -Huanp
sudo jiejie-masque --version
```

检查时区分 runtime watchdog、listener readiness、TUN/NAT deep probe 和客户端
实际转发。日志会避免记录 client identity、tunnel address、relay destination
和 resolved next-hop 等隐私信息。

## 11. 升级与回滚

升级步骤：

1. 下载新 binary 与 checksum，并核对 SHA256。
2. 备份当前 binary 和 YAML/EnvironmentFile。
3. 运行 `check-config`。
4. 原子替换 binary，重启对应 service。
5. 查看 `systemctl status`、journal 和实际客户端流量。

回滚时恢复上一个已验证 binary，重新运行 `check-config` 后重启。不要自动修改
配置；CONNECT-IP client 会 pin server public key，升级时不要无意更换 server
certificate/private key。

## 12. 故障排查

| 现象 | 优先检查 |
| --- | --- |
| CONNECT-IP 能连但网页打不开 | tunnel DNS、`127.0.0.1:53`、IPv4 forwarding、NAT/interface |
| 完全无法建立 | UDP/443、防火墙、TLS certificate、client public key |
| CONNECT-IP 无流量 | TUN、network prepare、`host_network.external_interface`、nft 规则 |
| CONNECT-UDP 返回 401 | username、`password_env`、EnvironmentFile 权限和内容 |
| 配置启动失败 | `jiejie-masque check-config --config PATH`、字段拼写和文件权限 |
| systemd 反复重启 | `journalctl`、ExecStartPre、watchdog/deep probe、端口占用 |
| DNS 请求失败 | 本机 `127.0.0.1:53` listener、gateway port 5353、UDP/TCP resolver |

## 13. 安全与边界

不要把 CONNECT-UDP unauthenticated mode 暴露到公网；不要把 DNS gateway 暴露
到公网；不要给 CONNECT-UDP service 增加 `CAP_NET_ADMIN`。`allow_private: true`
会放宽目标地址策略，只在可信网络使用。

Session NAT cleanup 使用 bounded two-worker executor，cleanup pending 地址不会
立即复用。F-302/F-404 仍需要真实 Linux/VPS reproduction；本手册不把 deferred
finding 描述成已解决问题。

当前正式 release 是 v1.0.10；本次 release 未部署 production。

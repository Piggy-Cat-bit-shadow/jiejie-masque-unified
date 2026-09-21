# jiejie-masque architecture

本仓库是单一 Linux CONNECT-IP MASQUE 服务端。架构、ownership 和运行时边界
见 [docs/architecture-lean.md](docs/architecture-lean.md)。外层 QUIC 使用维护
fork；TUN 数据面保持普通 bounded read/write，QUIC UDP GSO 仍由传输层负责。

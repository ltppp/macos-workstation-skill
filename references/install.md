# 配置与安装

## 支持基线与准备

宿主为 Apple Silicon macOS，客户机为 macOS 27；当前仅对 Lima 2.3.0-beta.1、sing-box 1.14.3 编写运行适配。确认主机磁盘可容纳完整 IPSW、稀疏客户机盘和保留旧实例；安装可能持续较长时间。不要为了省空间先删除旧盘。

从官方发行源获得软件：
- Lima：https://github.com/lima-vm/lima/releases/tag/v2.3.0-beta.1
- sing-box：https://github.com/SagerNet/sing-box/releases/tag/v1.14.3
- macOS IPSW：使用该版 Lima 官方 macOS 模板提供的 Apple 镜像来源与完整 SHA-256。

先验证下载归属与发行包校验，再把解压后二进制的 SHA-256 写入 profile。不能把“刚下载文件自己算出的哈希”当成已验证官方来源。分段下载必须检查各段、合并完整文件并校验整份 SHA-256；文件名、稀疏文件大小、HTTP 206 都不是完成证据。本包不重新分发第三方二进制和 Apple 镜像。

创建包外私有目录，复制 `examples/profile.json`，改为真实路径、校验值、用户自有节点与明确预期出口。profile 与节点文件均 chmod 600。示例的 192.0.2.10 是保留文档地址，不能用于实际网络。

当前节点支持范围沿用基线：VLESS IPv4:443、TCP、REALITY、Vision、Chrome TLS fingerprint、SNI www.cloudflare.com。不是通用订阅转换器；其他协议/拓扑需要另行适配验收。宿主物理网卡动态检测，不能把现有机器网关抄给其他用户。

`host_proxy_probe_port` 为宿主 Clash/Mihomo 的 HTTP/mixed 端口。没有这类代理可填 null，脚本会检查是否存在相关进程；检测到却没有可比较出口时不能验收通过。代理临时离线也属于未能完成检查，不把它视作“隔离已通过”。

## 命令顺序

```sh
python3 scripts/workstation.py --config /absolute/private/profile.json validate
python3 scripts/workstation.py --config /absolute/private/profile.json bootstrap
```

`bootstrap` 只创建全新实例，不覆盖存在实例。状态存放于 `~/.local/share/macvm-skill/<profile>`，LIMA_HOME、代理端口、凭据和剪贴板服务均独立。宿主代理若要添加节点专用物理路由，会触发管理员授权；完成前不得视作成功。

**引导限制：** 首次操作系统安装与第一次 SSH 可用之前，客户机 PF 尚未部署，默认 Lima 网络可能经宿主路由外出。当前版本不能保证从首次通电开始零直连。不要把浏览器业务使用放在这一阶段。如果用户要求安装流量也绝不能经过宿主代理，当前版本不满足，先停止并实现/验收宿主侧引导隔离，不得悄悄放宽要求。

bootstrap 会传送官方 sing-box 和安装脚本，然后在客户机 Terminal 打开安装窗口。用户在客户机输入管理员密码，检查退出码 0。配置只包含到宿主的转发凭据，不包含节点密钥。不要读取客户机初始密码文件发到聊天。

如首次打开终端时用户未登录桌面，登录后运行：

```sh
python3 scripts/workstation.py --config /absolute/private/profile.json install-network
```

安装使用 root 所有的固定 control 命令和限定 sudoers，不开放任意免密 root shell。它保留 Apple PF anchors，启用默认阻断后才给 Ethernet 临时地址，持久禁用 Ethernet IPv4/IPv6 自动启动。服务未装好时不能开始实际使用。

执行 [完整验收](acceptance.md)。首次启动、阶段安装成功都不产生 accepted.json。

# macOS Workstation Skill

在 Apple Silicon Mac 上创建和维护 macOS 虚拟机，包含专用代理、PF 断流保护、多目录共享、双向剪贴板、浏览器验收和重建。

基线：Lima 2.3.0-beta.1 · sing-box 1.14.3 · macOS 27 客户机。

## AI 执行入口

先读 [SKILL.md](SKILL.md)，按任务读取对应文档：

- [安装](references/install.md)：依赖、私有配置、节点、首次启动。
- [验收](references/acceptance.md)：代理、断流、冷启动、共享、浏览器与剪贴板。
- [重建](references/rebuild.md)：新实例验收、切换与回退。
- [维护](references/maintenance.md)：日常操作和共享调整。

命令在本目录执行，配置参考 [profile.json](examples/profile.json)，实际配置和节点保存在包外。

```sh
python3 scripts/workstation.py --config /absolute/private/profile.json <command>
```

新建顺序：`validate` → `bootstrap` → 客户机管理员完成安装 → `accept` → 登录桌面 → `finish-acceptance` → 用户确认双向剪贴板 → `confirm-ui`。

日常命令：`start`、`stop`、`shell`、`check`。重建使用新配置执行 `rebuild --from-config /absolute/private/old.json`，保留旧实例，通过验收后切换。

## 必测项

- 代理：预期出口、物理接口和路由、宿主 Clash/Mihomo 出口对比。
- 隔离：IPv4/IPv6、宿主代理与 DNS 绕路阻断；两种断流故障及恢复。
- 冷启动：网络保护、多目录读写策略、双向剪贴板。
- 浏览器：HTTPS、两台 STUN、WebGL。

检查失败不放行；实例、配置、节点或脚本变化后重新验收。

## 安装与状态

将本目录放入 `~/.codex/skills/macos-workstation` 或 `~/.claude/skills/macos-workstation`，也可直接引用本目录的 SKILL.md。

当前为开源预览版：15 项离线测试通过，新实例安装与重建端到端实测待完成。详见 [验证状态](references/validation.md)。

许可证：[MIT](LICENSE)。

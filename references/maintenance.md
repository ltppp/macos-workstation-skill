# 日常维护

## 进入与停止

```sh
python3 scripts/workstation.py --config /absolute/private/profile.json start
python3 scripts/workstation.py --config /absolute/private/profile.json shell
python3 scripts/workstation.py --config /absolute/private/profile.json check
python3 scripts/workstation.py --config /absolute/private/profile.json stop
```

shell 内 exit 只断开管理连接；stop 正常关闭客户机。门禁失败会撤销收据，需排查后重新完整验收，不要编辑收据放行。

## 多目录共享

每个 source 单独共享，target 在客户机用户家目录下，支持 writable true/false。不要把宿主外部路径的软链接放进已共享目录就声称能访问；链接目标仍需独立挂载。禁止共享整个宿主家目录或任何包含节点文件、私有运行目录和宿主 SSH 私钥的目录。

已存在实例添加共享：保存 profile 与实例 lima.yaml 的备份，正常停止对应实例，在运行 lima.yaml 中同步 mounts（只能修改这一个实例）。修改 profile 本身不会自动改写已有 Lima 实例配置，不能据此声称共享已生效。启动仍属于维护未验收阶段，重新运行完整验收；首次挂载目标父目录可能不存在，shares 检查会定位实际 VZ 卷并创建正确入口，不覆盖已有文件。

每个共享通过唯一临时标记定位卷、验证读取和写策略，结束清理自建标记。原项目文件不作为写测试材料。只读共享测试也要在宿主创建并删除标记，因此源目录需允许当前宿主用户写入；否则改用用户指定测试位置并说明缺少自动验收。

已知：基线环境跨宿主/客户机 flock 未实现可靠互斥，不要两端同时编辑同一文件。共享文件监控、依赖热更新、Git 锁协议需按项目分别验证。

## 剪贴板

已接受 profile 的运行脚本在其私有 runtime/scripts 下。桥接通过现有 SSH，每个 profile 独立 LaunchAgent。仅在用户桌面登录后可用，支持普通文本和白名单图片/富文本，单次最多 4 MiB；跳过敏感标记，不写内容日志、不保存历史。启动/重连只建立基线，不复制旧内容。

多个同时运行的 profile 不能同时开启共享同一宿主剪贴板的桥接；切换前关闭旧桥接，防止不同客户机之间意外交换内容。重建新实例只在切换或授权验证窗口启用其桥接。

## 故障处理

- 网络检查失败：保留证据，确认节点/路由、PF、DNS 注册和客户机脚本哈希；不能把重试通过覆盖第一次失败。每次失败报告另行保留。
- 管理员授权失败：SSH 中图形授权不可用时，使用客户机 Terminal；用户自己输入密码。
- PF Resource busy：脚本有限次重试，耗尽即失败。不可无限重试或临时关防火墙。
- 抓包：模板显式限定 IPv4，避免把 ARP 管理邻居请求误算公网泄漏；IPv6 另测，不能用这条过滤式证明 IPv6 无流量。
- 卸载：正常停止目标实例、关闭该 profile 剪贴板 LaunchAgent；确认无人使用后再停止该 profile 专用 sing-box。不要碰宿主 Clash、其他 Lima 实例或共享源目录。删除磁盘和私有状态必须有明确用户指令；分享公开问题报告前脱敏。

# 本期贡献与可复现证据

截至 2026-10-12。历史密码模块与 JWT 网关不计为本期全部原创工作。正式状态以对应 PR 和默认分支为准。

| 增量 | 公开记录 | 验证 |
|---|---|---|
| libsodium secretstream、随机发送端、文件互通、发布 | [PR #2](https://github.com/ChenJiasen-123/mb-secure-stream/pull/2)，已合并；Mooncakes 0.2.0 | 逐字节差分、异常输入、JS/Linux Native/WasmGC 指定宿主、独立安装 |
| 计数器溢出、七类畸形输入恢复、文件指标修正 | [PR #3](https://github.com/ChenJiasen-123/mb-secure-stream/pull/3)，已合并 | 计数器边界向量重生成、32 流/800 帧差分、重复测量 |
| MoonBit 0.10.15 CLI 格式与启动/写入修复 | [PR #4](https://github.com/ChenJiasen-123/mb-secure-stream/pull/4)，待合并 | 格式门禁、CLI 帮助/缺少构建、零进度写入清理 |
| 首页、架构图、安全恢复应用 | [PR #5](https://github.com/ChenJiasen-123/mb-secure-stream/pull/5)，待合并，依赖 #4 | 干净源码构建、10,000 条记录双向恢复、截断拒绝和已有文件保护 |
| 类型化标签/错误、公开读写接口 | [PR #6](https://github.com/ChenJiasen-123/mb-secure-stream/pull/6)，待合并，依赖 #5 | 158 项全仓、8 项 JS、公开应用、恢复及 FINAL 生命周期 |
| Poly1305 分配优化 | [PR #7](https://github.com/ChenJiasen-123/mb-secure-stream/pull/7)，待合并，依赖 #6 | 86 个独立大整数向量、全仓159项、前后三轮数据与原始哈希 |

PR #7 最终提交 `1336728a21271a45832353873b381a29ad431959` 的 [CI](https://github.com/ChenJiasen-123/mb-secure-stream/actions/runs/38246752776) 全部通过。测试数说明特定开发状态，不代表审计、独立用户人数或完整安全证明。

复现入口：[安装与验证](getting-started.md)、[试用指南](try-it.md)、[演示提纲](demo-script.md)。优化原始报告与文件校验值位于 [measurements](measurements/)；不要只展示有利指标，RSS 未显著改善也需说明。

尚未取得真实外部试用反馈，不虚构使用者、评价或获奖结果。后续真实反馈应记录公开链接、测试版本、问题及修复结果；未经同意不公开他人个人信息。

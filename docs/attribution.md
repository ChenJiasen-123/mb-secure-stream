# 来源与许可证

主体为 Apache-2.0。secretstream 参考 libsodium，保留其 ISC 许可与版权，见 [NOTICE](../crypto/mb-secretstream/NOTICE)。

| 当前组件 | 来源 | 本仓库改动 |
|---|---|---|
| `crypto/mb-chacha` | [moonbit-crypto/mb-crypto/mb-chacha](https://github.com/moonbit-crypto/mb-crypto/tree/main/mb-chacha)，Apache-2.0 | ChaCha20/XChaCha20 基础及 Bytes 便利接口 |
| `crypto/mb-poly1305` | [moonbit-crypto/mb-crypto/mb-poly1305](https://github.com/moonbit-crypto/mb-crypto/tree/main/mb-poly1305)，Apache-2.0 | Bytes 接口、块缓冲和打包分配优化；保留独立整数验证 |
| `crypto/mb-getrandom` | [moonbit-crypto/mb-crypto/mb-getrandom](https://github.com/moonbit-crypto/mb-crypto/tree/main/mb-getrandom)，Apache-2.0 | OS CSPRNG 基础与宿主接入 |
| `crypto/mb-secretstream` | 本仓库实现，协议参考 libsodium | 帧与状态机、随机发送端、类型化 API、完成策略与互通验证 |

Node 文件适配器、SQLite 备份和 OpenSeek 归档负责应用层文件生命周期；密码运算仍由 MoonBit 实现。Python/PyNaCl 用作独立 libsodium 对照。

OpenSeek 消费者固定依赖 `moonbitlang/openseek@0.6.2`（Apache-2.0）；公开 JSONL 测试日志的固定提交与 SHA-256 见 [OpenSeek 示例](../examples/openseek-archive/README.md#attribution)。上游日志保持原始字节，不计为本项目原创实现。

JWT/鉴权及其支持模块已迁往 [mb-jwt-gateway](https://github.com/ChenJiasen-123/mb-jwt-gateway)，其来源清单与许可证单独保留。删除模块与历史版本兼容关系见 [迁移说明](migration-0.3.md)。历史基础代码不因拆分而变成本期新创作。

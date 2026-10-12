# 架构与信任边界

## 协议与宿主分工

```mermaid
flowchart TB
    App[应用：文件备份、数据传输] --> Framing[应用层分帧和完整流完成策略]
    Framing --> Protocol[MoonBit secretstream 状态机]
    Protocol --> Cipher[XChaCha20 与 Poly1305]
    Protocol --> Entropy[安全随机头]
    Entropy --> Host[JS Web Crypto / Linux OS / WasmGC 宿主]
    Framing --> IO[宿主文件或传输 I/O]
    Oracle[独立 Python / libsodium] -. 密文与状态对照 .-> Protocol
```

密码计算由 MoonBit 实现。Node 文件适配器负责有界读写、临时文件和输出发布，不替代密码实现。Python 是独立互通参考，不是运行 MoonBit 库的必要依赖。

## 安全恢复的文件生命周期

```mermaid
flowchart LR
    Input[加密输入] --> Bounds[检查记录长度再分配]
    Bounds --> Auth[逐帧认证]
    Auth --> Temp[独占临时文件]
    Temp --> Complete{FINAL 和 EOF 均通过?}
    Complete -->|是| Publish[硬链接发布：不覆盖现有目标]
    Complete -->|否| Cleanup[删除临时文件]
    Auth -->|失败| Cleanup
    Bounds -->|失败| Cleanup
```

通过一帧认证只证明该帧，不能证明文件没有截断。临时文件内可能含已认证的部分明文，但不作为成功输出发布；依赖系统文件权限，并不保证存储介质擦除。

## 格式与限制

示例容器为 `MBSS0001`、24 字节头、重复的四字节小端长度和密文帧，末尾为空 FINAL 帧。它是项目自定义封装；内部帧才与 libsodium secretstream 兼容。每帧明文/AAD 上限各为 1 MiB，默认文件分块 64 KiB。

库不负责密码派生、密钥保存与恢复、网络重传、文件名与元数据恢复。JS、Linux Native、Node Web Crypto WasmGC 有运行证据；其他宿主需单独验证。实现未经安全审计，不能推导恒定时间或生产安全保证。

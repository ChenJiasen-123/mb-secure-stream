# secretstream 接口指南

包路径：`ChenJiasen-123/mb-secure-stream/crypto/mb-secretstream/src`。以下说明对应现有接口；类型化标签和结构化错误仍是计划中的改进。

在调用包的 `moon.pkg` 中导入：

```moonbit
import {
  "ChenJiasen-123/mb-secure-stream/crypto/mb-secretstream/src" @stream,
}
```

发送端通过 `init_push(Bytes)` 获取安全随机头，使用 `header()` 传给接收端。接收端通过 `init_pull_bytes(key, header)` 初始化。发送与接收均返回 `Result`，应用必须处理错误。

| 操作 | 责任 |
|---|---|
| writer.push(message, aad, tag) | 标签为 0 MESSAGE、1 PUSH、2 REKEY、3 FINAL；单帧/AAD 各不超过 1 MiB |
| reader.pull_bytes(frame, aad) | AAD 必须与发送端一致；成功返回明文与标签；认证失败不推进状态 |
| reader.finish() | 在传输 EOF 检查 FINAL 已收到；失败说明未完成，不能发布完整文件 |

FINAL 后继续发送或接收会失败。PUSH 不是整个流完成；REKEY 保持协议兼容但不替代密钥生命周期管理。禁止复用密钥/头组合；固定测试头和测试密钥仅用于测试。

完整接口签名见 [生成的公开接口](../crypto/mb-secretstream/src/pkg.generated.mbti)，互通约束及后端说明见 [模块文档](../crypto/mb-secretstream/README.md)。文件 framing 和失败不发布策略由应用层承担，参见 [架构](architecture.md)。

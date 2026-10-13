# secretstream 接口指南

包路径：`ChenJiasen-123/mb-secure-stream/crypto/mb-secretstream/src`。以下先说明 main 新增接口，再保留 0.2.0 兼容接口。新接口尚未发布到 Mooncakes，不能在安装 0.2.0 后直接使用。

在调用包的 `moon.pkg` 中导入：

```moonbit
import {
  "ChenJiasen-123/mb-secure-stream/crypto/mb-secretstream/src" @stream,
}
```

## 开发分支：类型化接口

`new_writer(key)` 返回 `StreamWriter`，`new_reader(key, header)` 返回 `StreamReader`。发送使用 `write(message, aad, tag)`，接收使用 `read(frame, aad)`，EOF 仍须执行 `finish()`。

标签为 `Message`、`Push`、`Rekey`、`Final`，无需填写数值。错误为 `StreamError`，可模式匹配 `InvalidKey`、`InvalidHeader`、`FrameTooLarge`、`TruncatedFrame`、`AuthenticationFailed`、`Finalized`、`MissingFinal` 等；底层熵源返回错误会包装为 `EntropyUnavailable(detail)`。Wasm 宿主异常仍可能 trap，并不保证转换为 Result。

认证失败后接收端状态不推进；`MissingFinal` 表示流未完成，不应发布完整文件。单帧上限、随机头和密钥生命周期边界与兼容接口相同。

公开接口可运行示例：

```sh
moon run examples/secretstream-typed --target js
```

查看 [示例源码](../examples/secretstream-typed/main.mbt)。只使用合成测试密钥，不能直接用于私人数据。

## 已发布 0.2.0：兼容接口

发送端通过 `init_push(Bytes)` 获取安全随机头，使用 `header()` 传给接收端。接收端通过 `init_pull_bytes(key, header)` 初始化。发送与接收均返回 `Result`，应用必须处理错误。

| 操作 | 责任 |
|---|---|
| writer.push(message, aad, tag) | 标签为 0 MESSAGE、1 PUSH、2 REKEY、3 FINAL；单帧/AAD 各不超过 1 MiB |
| reader.pull_bytes(frame, aad) | AAD 必须与发送端一致；成功返回明文与标签；认证失败不推进状态 |
| reader.finish() | 在传输 EOF 检查 FINAL 已收到；失败说明未完成，不能发布完整文件 |

FINAL 后继续发送或接收会失败。PUSH 不是整个流完成；REKEY 保持协议兼容但不替代密钥生命周期管理。禁止复用密钥/头组合；固定测试头和测试密钥仅用于测试。

完整接口签名见 [生成的公开接口](../crypto/mb-secretstream/src/pkg.generated.mbti)，互通约束及后端说明见 [模块文档](../crypto/mb-secretstream/README.md)。文件 framing 和失败不发布策略由应用层承担，参见 [架构](architecture.md)。

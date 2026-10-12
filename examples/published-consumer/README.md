# 独立发布包消费者

这是独立的 MoonBit 模块，只依赖 Mooncakes 上的 0.2.0，不引用仓库内的库源码。测试密钥为合成常量，仅用于示例。

```sh
cd examples/published-consumer
moon update
moon check cmd/main --target js --deny-warn
moon run cmd/main --target js
```

成功输出 `PASS: published secretstream package consumer`。示例验证 AAD 错误后的恢复、MESSAGE/PUSH/REKEY/FINAL 和结束后的发送拒绝。

如需自动在全新临时目录安装、运行并保存不含敏感信息的报告，在仓库根目录执行：

```sh
python tools/verify_published_install.py published-install.json
```

报告路径必须不存在。该过程需要访问 Mooncakes，可能使用配置好的注册表索引/下载缓存；“全新”指消费者工程与其依赖目录，不声称冷网络或清空了全局缓存。开发分支的类型化接口尚未包含在 0.2.0。

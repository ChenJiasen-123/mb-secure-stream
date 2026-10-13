# 十分钟试用与反馈

目标：验证能否按文档运行，并检查跨语言备份的完整性行为。无需真实文件或私人密钥。软件未经审计，试用不等于安全背书。

## 选择版本

- 已发布库：Mooncakes 0.2.0，运行 [独立消费者](../examples/published-consumer/README.md)。
- 新演示、类型化接口和优化：main 源码，已合并但新增接口和优化尚未发布到 Mooncakes。记录实际 `git rev-parse HEAD`，不要把它当作 0.2.0。

```sh
git clone --branch main https://github.com/ChenJiasen-123/mb-secure-stream.git
cd mb-secure-stream
git rev-parse HEAD
moon build --target js examples/secretstream-file/bridge
```

需要 MoonBit 0.10.15、Node 24、Python 3.12，以及支持同目录硬链接的文件系统。在 Python 虚拟环境中安装 `tools/requirements-dev.txt`，然后：

```sh
python examples/secure-backup/demo.py trial-backup.json
moon run examples/secretstream-typed --target js
python tools/verify_published_install.py trial-install.json
```

最后一条需网络，并独立安装 0.2.0；另外两条运行 main 源码。输出路径必须不存在，重复试用换用新报告名。

## 预期结果

演示输出 PASS；双方恢复的 10,000 条记录与哈希一致；截断拒绝、已有目标保护和临时目录清理字段为 true。类型化示例能从 AAD 失败恢复，FINAL 后拒绝发送。安装报告确认实际版本 0.2.0，消费者临时工程已清理。

## 反馈内容

请在 [本仓库 Issues](https://github.com/ChenJiasen-123/mb-secure-stream/issues) 自行提交：

- 操作系统、MoonBit / Node / Python 版本、分支或提交。
- 从哪一步开始失败，完整命令和脱敏错误。
- 是否依靠文档独立完成；最困惑的一处。
- 希望接入的真实场景，以及当前接口/文件格式是否满足需求。

不要上传密钥、私人明文、凭据或敏感数据。可附合成演示报告。没有实际反馈前，不宣称存在外部用户或已完成外部评审。

记录规范和待填反馈台账见 [外部反馈](external-feedback.md)。

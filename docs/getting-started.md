# 安装与复现

## 使用已发布库

发布版本为 [Mooncakes 0.2.0](https://mooncakes.io/docs/ChenJiasen-123/mb-secure-stream@0.2.0)。在自己的 MoonBit 工程根目录执行：

```sh
moon add ChenJiasen-123/mb-secure-stream@0.2.0
```

具体包路径、导入和完整流生命周期见 [secretstream 接口指南](secretstream-api.md)。发布包与 GitHub 开发分支可能不同；安装 0.2.0 不会得到尚未发布的改动。

## 从开发源码运行文件示例

以下从 main 构建；main 已包含文件恢复示例、类型化 API 和分配优化。安装 0.2.0 与运行开发分支是不同路径。

需要 MoonBit 0.10.15、Node 24，以及支持同目录硬链接的文件系统。Python 只用于独立互通验证，依赖建议安装到虚拟环境。

```sh
git clone --branch main https://github.com/ChenJiasen-123/mb-secure-stream.git
cd mb-secure-stream
moon check --deny-warn
moon test --deny-warn
moon build --target js examples/secretstream-file/bridge
node examples/secretstream-file/cli.cjs --help
```

文件操作、合成演示密钥生成和恢复安全边界见 [文件示例](../examples/secretstream-file/README.md)。只对自行创建的合成文件演示；自行保管密钥，密钥丢失不能恢复文件。

## 独立互通与异常输入

在已激活的 Python 虚拟环境中执行：

```sh
python -m pip install -r tools/requirements-dev.txt
python tools/verify_secretstream_files.py interop.json 1 --chunk-bytes 65536
python tools/verify_secretstream_differential.py differential.json --streams 32
node --test tools/test_secretstream_cli.cjs
```

第一条验证命令比较双方解密文件哈希，检查八类损坏输入、失败清理和已有输出保护。第二条对比 800 帧密文/明文/tag，并检查畸形输入拒绝后的恢复。结果是测试证据，不是安全审计。

常见问题：缺少 bridge 时先执行构建；已有输出必须换用新路径；缺少 FINAL 表示文件未完整接收；不支持硬链接的文件系统会拒绝发布，不能以覆盖写入绕过。

## 应用集成与反馈

文件加解密统一使用 [文件 CLI](../examples/secretstream-file/README.md)。需要真实数据格式的应用示例，选择 [SQLite 一致性备份](../examples/sqlite-backup/README.md) 或 [OpenSeek 会话归档与续接](../examples/openseek-archive/README.md)。各示例仅补充自身特有的步骤，不重复通用安装流程。

试用报告请包含提交或发布版本、系统和工具链、完整复现命令及错误信息。使用合成数据，不上传私钥、凭据或私人明文。报告路径必须不存在。独立试用不等于安全审计，见 [反馈记录规则](external-feedback.md)。

0.3.0 开发源码已收缩模块范围；JWT/网关使用者见 [迁移说明](migration-0.3.md)。历史合成备份演示的互通、截断与已有文件保护检查由上面的统一验证入口覆盖。

全新发布包消费者的详细命令见 [独立消费者教程](../examples/published-consumer/README.md)。

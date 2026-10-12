# 安装与复现

## 使用已发布库

发布版本为 [Mooncakes 0.2.0](https://mooncakes.io/docs/ChenJiasen-123/mb-secure-stream@0.2.0)。在自己的 MoonBit 工程根目录执行：

```sh
moon add ChenJiasen-123/mb-secure-stream@0.2.0
```

具体包路径、导入和完整流生命周期见 [secretstream 接口指南](secretstream-api.md)。发布包与 GitHub 开发分支可能不同；安装 0.2.0 不会得到尚未发布的改动。

## 从源码运行文件示例

需要 MoonBit 0.10.15、Node 24，以及支持同目录硬链接的文件系统。Python 只用于独立互通验证，依赖建议安装到虚拟环境。

```sh
git clone https://github.com/ChenJiasen-123/mb-secure-stream.git
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

## 一键备份与恢复演示

完成上述构建和依赖安装后，执行：

```sh
python examples/secure-backup/demo.py backup-demo.json
```

报告路径须不存在。[演示说明](../examples/secure-backup/README.md)包含双向恢复、截断拒绝、已有输出保护和应用边界。

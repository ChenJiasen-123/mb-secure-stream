# SQLite 加密快照备份与恢复

这是对 MoonBit secretstream 的实际应用接入：Python 标准库负责 SQLite 一致性快照和数据库检查；Node 只做文件 I/O；加解密仍由编译后的 MoonBit 实现执行。

## 构建与验证

需要 MoonBit 0.10.15、Node 24、Python 3.12，以及支持同目录硬链接的可信本地文件系统。在仓库根目录执行：

```sh
moon build --target js examples/secretstream-file/bridge
python -m pip install -r tools/requirements-dev.txt
python tools/test_sqlite_backup.py
```

测试只创建合成数据库，不访问用户数据库。它保留活跃 WAL 和未提交事务，检查已提交数据恢复，并使用 Python/libsodium 独立解密对比。其他测试覆盖损坏输入、非数据库内容、目标保护、发布竞态和清理失败。

## 备份自己的数据库

先创建一个新的二进制密钥文件，保存到受保护位置；示例命令不会覆盖已有密钥：

```sh
python -c "import os; f=os.fdopen(os.open('backup.key',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb'); f.write(os.urandom(32)); f.close()"
python examples/sqlite-backup/backup.py backup app.sqlite app-backup.mbss backup.key
python examples/sqlite-backup/backup.py restore app-backup.mbss restored.sqlite backup.key
```

输入可以替换为你有权备份的实际数据库。输出父目录必须已存在且可信，目标必须是全新文件。恢复还要求目标名对应的 `-wal`、`-shm`、`-journal` 均不存在，以免混入旧 sidecar。不要把恢复文件直接覆盖正在运行的数据库；先独立验证，再由应用执行停机切换。

每次命令返回 JSON。`outputCommitted: true` 表示已发布；若 `cleanupWarnings` 非空，按提示清理残留私有目录，不要盲目重试。密钥不会写入归档或报告；需另行安全备份，丢失后无法恢复。

## 备份与恢复流程

```mermaid
flowchart LR
    DB[SQLite main + WAL] --> Snapshot[SQLite backup API 一致性快照]
    Snapshot --> Private[0700 私有暂存目录 / 0600 文件]
    Private --> Moon[MoonBit secretstream]
    Moon --> Archive[完整加密归档]
    Archive --> Decrypt[MoonBit 验证 FINAL 与解密]
    Decrypt --> Check[SQLite integrity_check]
    Check --> Publish[硬链接发布全新目标]
```

使用 SQLite backup API 生成 main 数据库的一致性快照，包含已提交 WAL 数据。恢复时先完成解密和 SQLite integrity_check，再发布新的数据库文件。

`--timeout-seconds` 默认值为 120，最大值为 3600。快照、恢复检查和子进程执行分别使用对应的超时配置。暂存目录由命令创建和清理，清理报告通过 cleanupWarnings 返回。

参考：[SQLite Online Backup API](https://www.sqlite.org/backup.html)、[Python sqlite3.Connection.backup](https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.backup)。

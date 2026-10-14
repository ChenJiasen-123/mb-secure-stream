# 0.3.0 源码范围收缩与迁移

0.3.0 为开发源码版本，尚未发布到 Mooncakes。已发布的 0.2.0 不被覆盖，原包与 Git 历史继续可用。

本仓库只保留 secretstream、ChaCha、Poly1305、随机数及直接相关的文件适配、宿主示例、应用集成和独立验证工具。

JWT 与鉴权中间件迁往 [mb-jwt-gateway](https://github.com/ChenJiasen-123/mb-jwt-gateway)。使用者将模块前缀从 `ChenJiasen-123/mb-secure-stream` 改为 `ChenJiasen-123/mb-jwt-gateway`，JWT 和鉴权包后缀保持不变；独立项目的发布形式与版本以其 README 和 Releases 为准。

独立项目同样聚焦单一用途：HS256/ES256 JWT 和 issuer/audience 鉴权，不承接 Worker、限流、调度、连接池、指标、重放缓存或 ECDH。这些历史功能以及本库不再需要的 AEAD/HKDF，可从原 0.2.0 包或 [拆分前提交](https://github.com/ChenJiasen-123/mb-secure-stream/tree/bc8fa03c14d32534d4cb3412a6ff996314bf4f97) 找回。它们未被伪装成新的独立产品。

重复的试用和演示步骤统一到 [安装与验证](getting-started.md)。旧合成备份演示不再单独维护，其双向哈希、截断拒绝和已有输出保护由 `tools/verify_secretstream_files.py` 等独立验证工具覆盖。

采用 GitHub Actions 作为唯一持续集成入口，移除过时的 GitLab 配置。项目拆分导致全仓测试数下降，不表示保留组件的回归检查被放宽；当前证据应查看对应提交 CI，历史贡献与测量记录仍保留。

# 三分钟演示提纲

演示前按 [试用指南](try-it.md) 构建桥接、安装 Python 依赖。使用新的报告路径。

| 时间 | 展示 | 要说明的内容 |
|---|---|---|
| 0:00—0:30 | 首页与组件图 | MoonBit 实现密码运算；Node 做 I/O；Python/libsodium 是独立对端 |
| 0:30—1:30 | `python examples/secure-backup/demo.py live-demo.json` | 10,000 条合成记录双向恢复；对比报告中的哈希、截断拒绝和输出保护 |
| 1:30—2:00 | 恢复流程图 | 单帧认证不代表文件完整；FINAL+EOF 通过后才发布 |
| 2:00—2:30 | `moon run examples/secretstream-typed --target js` | 类型化标签、可区分错误、AAD 失败后的恢复；接口代码不放首页 |
| 2:30—3:00 | 分配分析与限制 | 展示前后三轮原始证据：耗时与累计分配减少，RSS 没有同步下降；未经安全审计 |

以上时间是讲解安排，不是对运行耗时的保证。不要用剪辑隐藏失败；网络安装提前完成，再展示独立安装报告。结束时说明 0.2.0 已发布，开发 API/优化仍待合并和发布。

证据入口：[贡献记录](contributions.md)、[测量与限制](allocation-optimization.md)、[架构](architecture.md)、[独立消费者](../examples/published-consumer/README.md)。

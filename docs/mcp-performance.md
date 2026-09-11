# MCP 读取性能与并发调优

本文记录 ZER-1049 的诊断、修复边界和运行建议。实现仍保持单 worker：
请求进入同一 FastAPI 进程，阻塞型 JSON-RPC 调度继续由现有线程桥接执行。

## 根因

`read_doc` 的主要延迟不在本地 Git 读取，而在 bearer token 验证：

1. 旧实现先从 PostgreSQL 读取全部 MCP token。
2. 它在数据库 session 尚未释放时逐条执行 bcrypt。
3. bcrypt 是 CPU 密集操作；token 数量增长后，请求会持有连接数秒。
4. 默认 SQLAlchemy QueuePool 为 5 个常驻连接和 10 个 overflow。16 个并发请求会让
   第 16 个等待连接，超过 pool timeout 后在 HTTP/MCP 边界退化为 `-32603 internal error`。

受控回归基线使用 20 个 token、每次 bcrypt 固定延迟 20ms、pool timeout 100ms：

| 指标 | 修复前 | 修复后 |
| --- | ---: | ---: |
| 顺序验证 p50 | 452.7ms | 27.2ms |
| 每个并发请求平均 bcrypt 次数 | 18.75 | 1.00 |
| 16 并发失败 | 1/16 | 0/16 |

相同条件下 p50 降低约 94%，约为原来的 1/16.6。并发成功结果均完成，
未再出现 QueuePool timeout。

## 修复

- 新 token 同时保存 bcrypt verifier 和 SHA-256 指纹。指纹只用于索引候选，
  bcrypt 仍是最终验证依据。
- bcrypt 在数据库 session 外执行，CPU 工作不再占用连接。
- 老 token 无法离线反推出指纹，因此首次成功验证仍走兼容扫描，然后惰性回填；
  无需停机批处理，也不改变已签发 token。
- bcrypt 后重新查询 token，保证验证期间被撤销的 token 不会成功返回。
- agent activity 改为 PostgreSQL `ON CONFLICT DO UPDATE`，消除同一 agent 首次并发读取时
  “先查再插”的唯一键竞争。
- 数据库连接池超时和数据库不可用现在分别返回稳定、可检索的错误：
  HTTP 503 的 `database_pool_timeout` / `database_unavailable`，以及 JSON-RPC
  `-32001` / `-32002`。未知异常仍保留标准 `-32603`。

## 观测

开启 DEBUG 日志后，每次 MCP token 验证输出固定字段：
`lookup_ms`、`bcrypt_ms`、`finalize_ms`、`candidates`、`legacy`。
日志不包含原始 token、token hash 或用户信息，可用于区分数据库查询、bcrypt 和提交耗时。

应用已有的 HTTP 请求时延指标继续覆盖端到端 transport 与工具调用。告警应分别统计
`database_pool_timeout`、`database_unavailable` 和剩余的 `-32603`，不要把三者合并。

## 连接池建议

先部署本修复并观察，不建议靠扩大连接池掩盖持有连接做 bcrypt 的问题。单 worker 默认
`pool_size=5`、`max_overflow=10` 通常足够；若数据库端允许并且实测仍有连接等待，
以“数据库可承受连接数 / 应用副本数”为上限逐步调整。pool timeout 应保持有限，让过载
快速返回可归因的 503，而不是让调用悬挂到客户端超时。

部署迁移后，新 token 立即走 O(1) 候选查找。老 token 的第一次请求仍可能较慢；
`legacy=true` 日志归零后，认证路径应稳定为一次索引查询、一次 bcrypt、一次最终确认。

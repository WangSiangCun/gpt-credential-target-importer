# Credential Target Importer

独立的 CPA / Sub2API 凭证导入能力包。

职责：

- 查询 CPA 账号状态和 401 / 额度耗尽状态
- 向 CPA 导入完整凭证
- 构建 CPA JSON 和 Sub2API JSON

网络会话由调用方注入，因此代理、超时和重试策略由上层项目控制；本包不保存数据库、不记录 token、不管理席位。

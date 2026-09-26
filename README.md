# Credential Target Importer

独立的 CPA / Sub2API 凭证导入导出 SDK，当前源码版本 0.2.0。

## 接口约定

- CPA 下载和管理接口上传统一使用 build_cpa_auth_file；build_cpa_json 为同一格式的入口。
- CPA 上传：POST /v0/management/auth-files，multipart file，Bearer 管理密钥。
- Sub2API 下载：sub2api-data v1 文件，包含 exported_at、proxies 和 accounts；账号 platform=openai、type=oauth。
- Sub2API 直接交付：POST /api/v1/admin/accounts/data，请求体 {data: 文件内容, skip_default_group_bind: false}，使用 x-api-key 管理密钥。
- Sub2API 的 HTTP 200 不代表账号导入成功：必须返回 account_created=1、account_failed=0 且无错误。
- target 参数仅为旧调用兼容，不作为 Sub2API 分组 ID 或订阅等级写入。

## 凭据边界

导出要求 email 和 AT。session、RT、真实 ID token 可选；缺少 RT 的文件不具有 SDK 所保证的长期刷新能力。SDK 不登录、不刷新、不保存凭据，不以字段非空代表远端认证成功。

CredentialBundle 的可选 id_token 仅接受调用方提供的真实 ID token，绝不以 AT 代填。account_id 可指定预期工作区；若 token 中的工作区不匹配或缺失，导出报校验错误。可提取的邮箱和 AT/ID token 工作区也会交叉校验。

JWT 解码只用于提取元数据，不验证签名。套餐只采用凭据自身的 claim；历史 plan_type 参数保留调用兼容但不制造 Team 权限。无套餐元数据时省略该字段。现有凭据若属于 Free/个人工作区，应由上层重新获取正确工作区凭据，修改导出标签不会改变权限。

## 网络与状态

网络会话由调用方注入，request 支持 headers、params、json_body、files、allow_redirects；代理、指纹及超时由上层拥有。SDK 使用同一会话，不创建直连后备请求。只跟随同来源且保留上传方法的 307/308，跨来源或改变 POST 方法的跳转返回明确错误。

status() 与 import_account() 的 CPA /api/account-status、/api/accounts/import 是保留的旧网关协议，不是标准 CLIProxyAPI 管理端协议。直接 CPA 应使用 import_auth_file()；未部署状态网关时状态探测报错。空响应、缺字段和未知状态不判正常；管理密钥 401 与账号凭据 401 分开处理。

SDK 不自动重试交付，防止网络结果未知时重复创建账号；异常 uncertain 表示应先核对目标端结果。错误提示不回显远端原始响应中的凭据。

## 开发与升级

在本目录执行 python -m pip install --no-deps -e .，再运行 python -m pytest tests -q。Team 的回归测试另在 team-seat-manager 目录运行。

0.2.0 的 Sub2API 下载结构替换了旧的单账号伪格式；调用方应读取 accounts[0].credentials。旧四个位置参数的 CredentialBundle 调用保持兼容。

发布时应先提交并发布 SDK，再将 Team requirements.txt 的 Git revision 更新为已发布的精确提交；不要指向未推送的本地 revision。当前修复不自动推送、部署或改写线上数据库。

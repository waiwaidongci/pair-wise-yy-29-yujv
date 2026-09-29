# 数字凭证签发、验证和撤销服务

标准库 Python 3.11+ 实现，使用 SQLite 保存密钥版本、模板、凭证、争议和审计记录。服务支持最少字段披露、离线签名的在线撤销复核、密钥轮换和证件状态争议。

## 初始化与启动

```bash
python3 app.py --init --seed
python3 app.py
```

默认地址 `http://127.0.0.1:8211`，也可使用 `--port` 与 `--db` 覆盖端口和数据库路径。身份使用 `X-Actor`、`X-Role` 请求头，角色为 `issuer`、`holder`、`agent` 或 `regulator`。

## 主要接口

- `POST /api/keys/rotate`：签发方轮换密钥。
- `POST /api/templates`：创建凭证模板。
- `POST /api/credentials`：签发凭证，支持幂等键。
- `POST /api/credentials/{id}/present`：按持有人选择披露字段并生成令牌。
- `POST /api/credentials/{id}/delegations`：持有人登记代出示委托（代理人、可见字段、截止时间）；同一代理人只保留一份未结束委托，新登记自动作废旧委托。
- `POST /api/delegations/{id}/present`：代理人凭委托生成令牌（角色 `agent`，需 `idempotency_key`）。签发方冻结、凭证撤销/争议、委托结束/过期分别按各自原因拒绝；重复请求沿用首次令牌，并发提交只成功一次。
- `POST /api/issuer/freeze`、`POST /api/issuer/unfreeze`：签发方冻结/解冻本机构。冻结后委托待办保留、出示停用；解冻只恢复当前仍有效的凭证和委托。
- `POST /api/verify`：验证令牌，可指定验证时间与在线/离线模式。密钥轮换后老委托按登记时密钥版本验签，新委托走新版本。
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。

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
- `POST /api/verify`：验证令牌，可指定验证时间与在线/离线模式。
- `POST /api/credentials/{id}/revoke`：签发方撤销凭证。
- `POST /api/credentials/{id}/dispute`、`POST /api/disputes/{id}/resolve`：提出和处理撤销争议。
- `POST /api/delegations`：持有人登记受控代出示委托（代理人、可见字段、截止时间）。同一代理人重新登记会自动把旧委托置为 `superseded`，只保留一份未结束委托。
- `POST /api/delegations/{id}/present`：代理人凭委托生成令牌（角色 `agent`，需 `idempotency_key`）。签发方冻结、凭证撤销/争议/过期、委托过期/撤销/被取代分别以独立错误码 `issuer_frozen`、`credential_revoked`、`credential_disputed`、`credential_expired`、`delegation_expired`、`delegation_revoked`、`delegation_superseded` 拒绝；重复请求沿用首次令牌，并发提交只成功一次。
- `POST /api/delegations/{id}/revoke`：持有人提前撤销委托。
- `POST /api/issuer/freeze`、`POST /api/issuer/unfreeze`：签发方冻结/解冻本机构。冻结不改任何既有记录（争议待办保留），仅停用人和代理人的出示与在线复核；解冻只恢复当前仍有效的凭证和委托。
- `GET /api/state`、`GET /api/health`：查看状态和健康检查。

### 密钥轮换与代出示

委托在登记时钉住签发方当前密钥版本（令牌载荷 `key_version`）。轮换后，老委托生成的令牌继续按签发时的旧版本验签（验证结果 `key_retired=true`），新登记的委托走新版本。在线验证会重新复核委托与冻结状态；离线验证只能依赖令牌内签名和到期时间。

### 分层

请求入口（`Handler` 路由）、状态判定（`DelegationPolicy` 纯函数）与记录保存（`Store` 的 SQL/事务，写操作经 `Store.write()` 串行化）相互独立；`DelegationService`/`FreezeService` 只做编排。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

这是本地原型：私钥保存在 SQLite 中，离线验证只能依赖令牌内的到期时间，真实撤销仍需在线检查；也未实现可验证凭证联盟标准或硬件密钥保护。

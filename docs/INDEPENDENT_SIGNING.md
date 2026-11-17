# AltasCI 证书管理

实现依据为 `new-feat-doc/AltasCI-Independent-Signing-Client-Integration-Spec-v1.0.md`。这是独立签发协议，使用实例专属 Bearer Token；不使用此前移除的 PKI Console OAuth 集成。

## 第一次使用

1. 解锁保险库，打开“AltasCI 证书管理 → 连接与凭据”。填写连接名称、完整 `https://公开主机/signing/<实例 UUID>/issue` 地址和 `ist_...` Token。
2. 如果 HTTP 入口要求客户端证书，勾选“此端点要求 mTLS”，选择通信 P12/PFX，或客户端 PEM 证书链及其配对 PEM 私钥。输入密码后点击“保存连接并加载通信身份”。密码不保存；重新解锁或切换连接后须重新加载身份。
3. HTTPS 服务器使用私有 CA 时，另选“服务器信任根”。需要验证业务签发结果的私有 CA 时，另选“业务签发证书信任”中的 PEM 根 CA；必须通过独立可信渠道取得。
4. 可先下载签发者 CA 检测 HTTPS。此操作不发送 Token，因此成功只说明入口可达，不能证明 Token 有效或具有签发权限。
5. 在“证书与签发任务”中新建申请。默认使用当前用户 CNG 的 ECDSA P-256 不可导出私钥，也可选 P-384、RSA 2048/3072/4096。填写 Subject 和至少一个 DNS/IP/email/URI SAN。CN 可为空；非空时须与一个 SAN 身份一致。
6. 选择预期 EKU 和有效期。预期 EKU 只验证返回结果，不覆盖服务端策略。CSR 只添加 SAN 扩展；不会加入 KU/EKU/BasicConstraints。
7. 点击“保存并签发”。先保存原始 JSON 字节、幂等键、端点和原 Token 摘要，再发送请求。签发后分别显示证书状态、业务链信任和本地私钥关联情况。
8. 证书验证通过后可显式安装到 Windows 个人存储，也可导出叶 PEM 或完整链 PEM。完整链包含叶证书和上级 CA。新生成的业务私钥保留在 CNG，不提供私钥文件导出；无本地私钥的外部 CSR 结果可导出给原私钥持有者。

## CSR 与 HTTP 签发接口

已对照 `phil616/altasci-public-pki` 的 `single` 分支、提交 `53b528d1e7d7f3cb6824eb4bb2d315dec63589c1`，检查实际路由、JSON 解码、CSR 校验和证书签发代码。`POST /signing/{id}/issue` 接收的 JSON 只有 `csr_pem` 和 `validity_seconds`；服务端不替客户端生成业务私钥。

“本地生成 CSR 后签发”先在 Windows CNG 创建私钥，再用独立签发专用配置生成 PKCS#10：关闭 CertEnroll 默认扩展，清空初始化扩展后只添加 SAN。KU/EKU 由服务端策略决定。CSR 统一输出标准 `CERTIFICATE REQUEST` PEM，避免 Windows 的 `NEW CERTIFICATE REQUEST` 包装被服务端拒绝。Subject 按 ASN.1 字符串类型解码，支持 Windows 生成的中文 BMPString。

导入 CSR 时，允许将 Windows 的旧 PEM 包装规范化为标准包装，保留原始 DER、签名、Subject 和扩展；不会删除外部 CSR 中不被服务端支持的扩展。已保存任务的精确请求字节和幂等键不做修改；新规则仅用于新建任务。旧任务仍按原请求恢复。

## 几种凭据各自的用途

| 配置项 | 用途 | 保存方式 |
|---|---|---|
| HTTP 通信客户端证书和私钥 | 向 nginx 等入口进行 mTLS 身份认证 | 文件由用户保管；加载后仅在当前解锁会话的 TLS 配置中使用，密码不保存 |
| HTTPS 服务器信任根 | 验证 API 服务器证书链与主机名 | 保险库保存所选文件路径，按连接加载 |
| 实例签发 Token | 授权 issue/read/revoke 业务操作 | Windows 凭据管理器；保险库只存摘要、用户提供的 scopes/到期时间 |
| 业务叶私钥与 CSR | 申请并使用业务叶证书 | 新私钥位于当前用户 CNG；CSR 和容器引用位于 SQLCipher |
| 业务信任根 | 验证业务签发证书链 | 从独立可信渠道选择的 PEM CA，加上系统根；不会自动提升下载的 CA 为信任锚 |
| 所有者 Cookie、CSRF 和密码 | 管理实例、策略、凭据、历史证书 | 独立网络会话，仅内存，不持久化 |
| 所有者导入的 CA 私钥 | 供服务端签发叶证书 | 明确确认后上传至 Console 服务器；本应用不保存 CA 私钥或原始管理请求体 |

公开签发与所有者管理分别配置 TLS 身份、代理、超时、服务器根和网络会话。二者不会互相发送 Token、Cookie 或 CSRF。入口要求 mTLS 并不替代任何一种业务认证。

## 任务恢复、查询、续期和吊销

- Holder API 无证书列表。列表由本地任务和证书 UUID 组成；可手动输入已知 UUID 查询，但必须使用原 Token。
- 超时、断线、5xx、响应损坏或本地响应验证失败时，保留原任务。选择原连接，加载其通信身份，点击“恢复原请求”。请求使用原 Token、相同幂等键和完全相同的 JSON 字节；不重新序列化报文。
- Token 更新不会接管旧 Token 的历史。客户端会检查凭据摘要，防止在原任务下换 Token 误签。任务存在时不能把连接改到另一端点。
- 429 的 Retry-After 会持久化，重启后继续等待；不进行隐式重试或无界轮询。
- 不确定的原任务须先恢复/核对，再发起续期。续期创建新的 CNG 私钥、CSR、任务和幂等键；不自动替换外部服务证书或执行 reload。
- 到期状态每分钟刷新，证书距到期 7 天内显示提醒。Token 到期由用户输入或所有者提供，单独显示。
- 吊销前展示 Subject、SAN、十进制序列号、SHA-256 指纹和原因，并要求确认。允许 0、1、2、3、4、5、6、9、10；包括 6 在内均不可恢复。原因在发送前保存，结果不确定时只能保留原原因重试。
- CA DER/PEM 和 DER CRL 可单独下载、导出。CRL 解析会核对签发者签名、更新时间和本实例 URL 的 critical IDP 叶证书作用域；不会宣称替用户配置了目标应用的完整撤销验证。

## 所有者管理

配置 `https://管理主机/api/v1` 和该入口所需的独立通信身份后，用用户名/邮箱及密码登录。无需 OAuth。

- 查看、刷新自己拥有的实例和完整详情。
- 导入匹配的 CA PEM、未加密 CA 私钥和上级链，创建独立实例。界面明确要求确认 CA 私钥会被上传并由服务器保存。
- 使用结构化表单编辑完整策略、名称与启用状态；更新时显式发送 `enabled`，不就地替换 CA 材料。
- 创建带 scopes、1 小时～90 天有效期、累计额度、分钟限速及可选附加完整策略的 Token。明文仅在创建成功窗口出现一次，默认掩码；显示或复制均由用户主动操作。
- 查看凭据元数据、撤销凭据。撤销 Token 不会自动吊销此前的叶证书。
- 按游标浏览每页 100 条证书历史，并确认吊销本实例证书。
- 实例/Token 创建响应丢失时保留待核对标记，阻止盲目重复创建；须先刷新相关列表核对，再确认继续。丢失明文的 Token 应撤销后重新创建。

## 持久化和锁定

保险库架构版本 3 新增 `independent_signing_records`，支持从版本 1、2 自动迁移，保留旧申请、远程元数据、历史连接表和审计记录。新保险库不创建旧连接表。

业务 Token 明文、通信私钥、通信密码、所有者密码/Cookie/CSRF 和上传的 CA 私钥不写入该表。签发请求正文仅包含公开 CSR 和有效期，以 Base64 保留其精确 UTF-8 字节。

锁定或退出会取消在途请求、清除网络会话和加载的通信身份，并关闭敏感弹窗、清空密码与一次性 Token。已保存的在途签发任务在下次解锁时标记为结果未知，供用户原样恢复。

## 验证范围

新增 `certmgr_signing_tests` 覆盖 URL/Token、CSR、证书字段和密钥配对、业务信任边界、PFX/PEM 通信身份、真实 TLS/mTLS、nginx 缺证书提示、重定向、报文原样重试、Cookie/CSRF 隔离、限速及 CRL 作用域。

新增 `certmgr_signing_vault_tests` 覆盖精确字节恢复、吊销原因持久化、数据库加密、锁定访问和 v1/v2 保险库迁移。

`certmgr_independent_enrollment_tests` 必须在 Windows 上实际创建临时 CNG 密钥，覆盖 ECDSA P-256/P-384、RSA 2048/3072/4096、中文 Subject 和 DNS/IP/email/URI SAN；测试结束删除密钥。此套测试不依赖可跳过的环境开关。设置 `APCM_CSR_FIXTURE_DIR` 可输出公开 CSR 和原始请求 JSON，供以下命令验证：

```powershell
.\scripts\verify-independent-csr.ps1 -FixtureDirectory $env:APCM_CSR_FIXTURE_DIR
```

脚本获取上述固定提交，将适配测试加入临时检出目录，直接调用服务端原有 HTTP JSON 解码器、CSR 解析器、策略校验器及临时 CA 签发器。`.github/workflows/validate-signing.yml` 在 Windows 构建和 CTest 后运行这项互操作检查。它不启动 PostgreSQL，不覆盖远程身份认证或生产部署联调。

自动化测试使用临时 CA、临时端点和临时保险库，不访问生产签发服务。真实部署还需使用部署方提供的端点、通信身份、业务信任根和测试凭据进行端到端联调。

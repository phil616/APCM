# Architecture

## Authority boundaries

```text
Qt Quick UI
    ↓
AppController / services
    ↓
platform interfaces
    ├── WindowsCertificateStore → Crypt32 / Windows Certificate Store
    ├── WindowsCngKeyProvider   → NCrypt / KSP / TPM
    ├── WindowsCertEnrollBackend→ CertEnroll / pending request state
    └── SqlCipherVault          → encrypted application metadata only
```

`src/domain` 和 `src/services` 不包含 Windows API 头文件。Windows handle、COM interface 和 native error 只能出现在 `src/platform/windows`。未来 Linux/macOS 后端应实现相同接口，而不是向 domain 泄漏平台路径。

## Certificate stores

| Domain scope | Domain role | Windows mapping |
|---|---|---|
| User | Personal | `CurrentUser\MY` |
| Machine | Personal | `LocalMachine\MY` |
| User / Machine | TrustedRoot | `Root` |
| User / Machine | IntermediateCA | `CA` |
| User / Machine | EnterpriseTrust | `Trust` |

证书内部 ID 为 `scope | role | SHA256(DER)`。CN 仅用于显示，不能作为身份键。

## Vault envelope

```text
master password ──Argon2id──> KEK
random DB_KEY ──XChaCha20-Poly1305(KEK)──> vault.meta
vault.db ──SQLCipher(DB_KEY)──> encrypted metadata
```

修改主密码只需重新封装 `DB_KEY`。`enrollment_requests` 保存 provider/container 引用、摘要、公开 CSR、申请有效期和工作流状态，不存在 private key 列。数据库删除不会触碰 Windows Certificate Store 或 CNG。架构版本 2 增加了申请名称、申请有效期和 CSR 字段，并会从版本 1 自动迁移。

## Elevation

`CertificateManager.exe` 普通权限运行。机器级 CSR 创建、签发响应安装、证书和 P12/PFX 导入调用 `CertificateManager.Helper.exe`，由 Windows `runas` 触发 UAC。Helper 只接受白名单动作；证书安装会重新解析文件并核对预览时的 SHA-256 指纹，根存储额外检查 `CA=true`。机器 CSR 配置和生成结果通过自动删除的 JSON 临时文件交换；机器级 P12/PFX 密码不会进入命令行，而是以当前用户 DPAPI 临时封装文件传递，Helper 解密使用后立即清零，主程序随后删除临时文件。

## Certificate installation

统一安装管线支持单张 DER/CRT/CER、PEM 证书以及包含多张证书的 PEM 链。P12/PFX 先使用 `PFXVerifyPassword` 校验密码，再由 `PFXImportCertStore` 导入证书及 CNG/CAPI 私钥引用。用户明确选择 `CurrentUser`/`LocalMachine` 与 `MY`/`Root`/`CA`/`Trust`，根存储始终要求单独确认。

每一张通过 APCM 安装的证书都会以 SHA-256 指纹、作用域和存储角色写入 SQLCipher `certificate_references`。Windows Certificate Store 仍是安装状态的权威来源；APCM 记录只表示管理归属。

## Enrollment

设备模板在模板校验和 CertEnroll 两层强制：

- `ContextMachine`
- `Microsoft Platform Crypto Provider`
- RSA 2048
- `XCN_NCRYPT_ALLOW_EXPORT_NONE`
- EKU `1.3.6.1.5.5.7.3.2` (`clientAuth`)

`CreateRequest()` 直接返回 PKCS#10 文本，并将该公开请求材料加密保存到 SQLCipher 以便后续查看和提交。只有用户主动复制或提交时 CSR 才离开 APCM；私钥不会离开 CNG provider。

申请界面允许配置 CN/O/OU/L/ST/C、DNS/IP/URI/UPN SAN、用户或计算机作用域、软件 KSP 或 TPM、RSA 2048/3072/4096、导出策略、Key Usage 与标准或自定义 EKU。TPM 强制不可导出并限制为 RSA 2048。用户填写的“申请有效期”属于提交给 CA 的工作流元数据，因为 PKCS#10 本身不定义最终证书有效期；最终值由 CA 策略决定。

CA 返回叶证书后，APCM 不再创建空的 CertEnroll 会话。它从加密申请记录恢复 CNG Provider 与 Container，设置 `CERT_KEY_PROV_INFO_PROP_ID`，再用 `CryptAcquireCertificatePrivateKey` 的 CNG 与 `CRYPT_ACQUIRE_COMPARE_KEY_FLAG` 路径核对证书公钥。只有匹配成功才将证书写入对应的 Windows `MY` 存储；枚举证书也显式优先 CNG，避免把有效的 CNG/TPM 私钥误报为缺失。

## APCM managed certificates and roots

APCM 管理证书是 SQLCipher 中对 Windows 证书指纹的引用。所有经统一安装管线或签发响应安装的证书都会自动登记；已有第三方根证书也可手动加入。移出管理不会删除 Windows 证书，删除 Windows 证书也不会自动删除关联私钥。

## PKI connections

手动连接使用 `ManualCAConnector` 准备外部交接，但不会伪装成已经联系 CA，也不会把申请错误标记为已提交。通用 HTTP 连接会严格检查 HTTP 状态，并以 `application/pkcs10` 将 CSR 实际 POST 到配置地址。它不是完整的 EST、SCEP 或 ACME 协议实现。V1 不在连接配置中保存口令或 API 密钥。

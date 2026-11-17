# APCM

APCM（AltasCI multi-Platform Certificate Manager）是基于 Qt 6 / C++20 的原生证书管理与申请程序。当前 Windows 后端统一管理 Windows Certificate Store、CNG/KSP 和 TPM，但不创建新的证书存储，也不承担 CA 签发职责。

## 当前实现

- 枚举 `CurrentUser` / `LocalMachine` 的 `MY`、`Root`、`CA`、`Trust`
- 解析证书主体、颁发者、序列号、SHA-1/SHA-256 指纹、有效期、EKU、CA 属性，并可一键复制 SHA-256 指纹
- 使用 Windows Chain API 构建并检查证书链
- 区分证书与私钥，显示 CNG Provider、Container、TPM 与导出策略
- 枚举 Windows CNG 持久化密钥并检测 Microsoft Platform Crypto Provider
- 使用 CertEnroll 直接生成 PKCS#10；可选择 CurrentUser/LocalMachine、Microsoft Software KSP 或 Microsoft Platform Crypto Provider（TPM）、RSA 长度与导出策略
- 支持查看、复制和导出 CSR，交由外部 CA 签发后安装返回的证书
- 创建申请时可自定义完整 X.500 主题、DNS/IP/URI/UPN SAN、Key Usage、标准或自定义 EKU 与期望有效期，并加密保存 CSR 和申请状态
- 安装签发响应时依据申请记录恢复 CNG Provider/Container，使用公钥比对拒绝错误证书，再写入 `CERT_KEY_PROV_INFO`，确保签发证书可实际调用原私钥
- 使用 SQLCipher 保存应用元数据，使用 libsodium Argon2id + XChaCha20-Poly1305 封装随机数据库密钥
- 从 Windows 根存储选择第三方根证书加入 APCM 管理清单；移出清单不会删除 Windows 证书
- 安装 PEM、CRT、CER、DER 证书及多证书 PEM 链；安装 P12/PFX 时验证密码并导入关联私钥
- 可选择当前用户或本地计算机的个人、根 CA、中间 CA、企业信任存储；通过 APCM 安装的证书自动加入加密管理清单
- 实时显示可枚举的 CNG/KSP 密钥，并区分 TPM、硬件与软件密钥
- “AltasCI 证书管理”：独立签发 Token、SAN-only CSR、可恢复签发任务、查询/导出/吊销、CA/CRL，以及隔离的实例所有者管理
- 独立配置 HTTP 通信 mTLS（PFX 或 PEM）、HTTPS 服务器根、业务证书信任根、代理与超时；缺少通信证书时给出专门提示
- 结构化、版本化证书模板与可查询的本地加密审计日志
- 全中文 Qt Quick / QML 传统 Windows 管理控制台界面，英文使用 Consolas、中文使用黑体
- 显式安全退出与窗口关闭锁定：关闭 SQLCipher 连接、清零内存数据库密钥并保持加密数据持久化
- Windows 内核互斥锁与本地 IPC 双重单实例保护；重复启动只会还原并激活已有窗口

## 安全边界

- 私钥永不进入 SQLCipher。
- TPM 设备模板永不生成可导出私钥。
- 机器作用域的 CSR 创建和签发响应安装通过白名单 UAC Helper 执行，不静默降级到用户或软件密钥。
- Windows Certificate Store 是证书当前状态的权威来源。
- CNG/KSP 是私钥当前状态的权威来源。
- 删除证书不会删除关联私钥。
- P12/PFX 密码仅用于当前安装，不写入 SQLCipher、日志或命令行；机器级导入通过 DPAPI 临时封装后交给 UAC Helper。
- 客户端模板只减少错误，服务端 CA / Enrollment Gateway 必须执行最终策略。

使用方法和凭据边界见 [AltasCI 独立签发说明](docs/INDEPENDENT_SIGNING.md)。

## 构建

依赖路径已经写入 `CMakePresets.json`：

```powershell
.\scripts\build.ps1
```

脚本会自动定位 Visual Studio 的 MSVC x64 Developer Prompt，随后配置、构建并运行测试。
默认依赖路径为 `D:\Qt\6.8.3\msvc2022_64` 与 `D:\Tools\vcpkg`；其他机器可通过 `QT_ROOT`、`VCPKG_ROOT` 环境变量覆盖。vcpkg registry baseline 已固定，依赖解析可复现。
脚本也会运行 `windeployqt`，因此构建目录中的程序可以直接启动，无需临时修改 `PATH`。

运行：

```powershell
.\build\debug\CertificateManager.exe
```

首次启动会在 `%LOCALAPPDATA%\DreamReflexOpenSource\Certificate Manager\` 创建 `vault.meta` 和加密的 `vault.db`。

## 生成 MSI 安装包

```powershell
.\scripts\package.ps1
```

脚本会自动读取 `CMakeLists.txt` 中的项目版本，执行 Release 构建、QML lint、核心测试、Qt 运行库部署和 WiX 5 打包，输出
`build\package\APCM-<版本>-x64.msi`。安装包为 x64、per-machine 单文件 MSI，CAB 已内嵌；
安装向导允许选择安装目录，以及是否创建开始菜单和公共桌面快捷方式；安装后会创建“应用和功能”卸载项，并支持相同 UpgradeCode 下的
后续大版本升级。MSVC、libsodium、SQLCipher 与 OpenSSL Crypto/SSL 运行时均采用应用本地部署，
目标机器不需要另行运行 VC Redistributable。

卸载只删除安装器部署的程序文件、快捷方式和产品注册信息，不删除 `%LOCALAPPDATA%` 下的用户
加密保险库。当前构建流程不会伪造代码签名；正式分发前应使用组织持有的受信任代码签名证书签署 MSI。

## GitHub 自动发版

推送到 `main`、推送 `v*` Tag 或手动运行“构建并发布 APCM MSI”工作流时，GitHub Actions 会读取
`CMakeLists.txt` 的 `project(... VERSION X.Y.Z)`。尚未发布该版本时，工作流在 Windows Runner 上完成
构建、QML lint、测试和 MSI 封装，核对 Tag 指向构建提交，再上传 MSI 和 `.sha256` 到草稿，附件齐全后正式发布。
已存在的普通 Tag 不会阻止首次发布；已有正式 Release 会跳过，已有草稿则停止供核查恢复。

发布新版本时先同步 `CMakeLists.txt` 与 `vcpkg.json` 的版本，再将提交推送到 `main`。
也可在该提交上创建并推送同版本标签，例如 `v0.1.3`；只推标签而不修改项目版本会明确报错。
已正式发布的版本不能移动 Tag 或覆盖附件；MSI 升级要求三段式版本号持续递增。

## 权限说明

应用默认以普通用户运行。读取 LocalMachine 存储通常不需要提升权限；写入 LocalMachine 证书或导入机器级 P12/PFX 时，由受限的 elevated helper 请求一次性 UAC 授权。当前版本不会让整个 GUI 常驻管理员权限。

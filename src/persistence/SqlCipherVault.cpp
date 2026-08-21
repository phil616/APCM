#include "SqlCipherVault.h"

#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QScopeGuard>

#include <sodium.h>
#include <sqlcipher/sqlite3.h>

#include <algorithm>

extern "C" int sqlite3_key(sqlite3 *db, const void *key, int keySize);

namespace certmgr::persistence {
namespace {

constexpr auto kMetadataFile = "vault.meta";
constexpr auto kDatabaseFile = "vault.db";
constexpr auto kAad = "certmgr-vault-v1";

void bindText(sqlite3_stmt *statement, const int index, const QString &value)
{
    const QByteArray bytes = value.toUtf8();
    sqlite3_bind_text(statement, index, bytes.constData(), bytes.size(), SQLITE_TRANSIENT);
}

QString columnText(sqlite3_stmt *statement, const int index)
{
    const auto *value = sqlite3_column_text(statement, index);
    return value ? QString::fromUtf8(reinterpret_cast<const char *>(value)) : QString{};
}

domain::EnrollmentState enrollmentStateFromName(const QString &name)
{
    using enum domain::EnrollmentState;
    if (name == QLatin1String("KEY_CREATED")) return KeyCreated;
    if (name == QLatin1String("CSR_CREATED")) return CsrCreated;
    if (name == QLatin1String("SUBMITTED")) return Submitted;
    if (name == QLatin1String("PENDING")) return Pending;
    if (name == QLatin1String("ISSUED")) return Issued;
    if (name == QLatin1String("INSTALLED")) return Installed;
    if (name == QLatin1String("DENIED")) return Denied;
    if (name == QLatin1String("FAILED")) return Failed;
    if (name == QLatin1String("REVOKED")) return Revoked;
    return Draft;
}

domain::AppError vaultError(QString code, QString message, QString details = {})
{
    return {domain::ErrorCategory::Vault, std::move(code), 0, std::move(message), std::move(details)};
}

} // namespace

struct SqlCipherVault::VaultMetadata {
    int version{1};
    QByteArray salt;
    quint64 opsLimit{crypto_pwhash_OPSLIMIT_MODERATE};
    quint64 memLimit{crypto_pwhash_MEMLIMIT_MODERATE};
    QByteArray nonce;
    QByteArray encryptedDatabaseKey;
};

SqlCipherVault::SqlCipherVault(QString directoryPath)
    : directoryPath_(std::move(directoryPath)), cryptoReady_(sodium_init() >= 0)
{
}

SqlCipherVault::~SqlCipherVault() { lock(); }

QString SqlCipherVault::databasePath() const { return QDir(directoryPath_).filePath(QLatin1String(kDatabaseFile)); }
QString SqlCipherVault::metadataPath() const { return QDir(directoryPath_).filePath(QLatin1String(kMetadataFile)); }

bool SqlCipherVault::exists() const
{
    return QFileInfo::exists(metadataPath()) && QFileInfo::exists(databasePath());
}

bool SqlCipherVault::isUnlocked() const { return database_ != nullptr; }

tl::expected<SqlCipherVault::VaultMetadata, domain::AppError> SqlCipherVault::readMetadata() const
{
    QFile file(metadataPath());
    if (!file.open(QIODevice::ReadOnly))
        return tl::unexpected(vaultError(QStringLiteral("vault.meta_read"),
            QStringLiteral("无法读取保险库元数据。"), file.errorString()));
    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(file.readAll(), &parseError);
    const auto object = document.object();
    if (parseError.error != QJsonParseError::NoError || object.value(QStringLiteral("version")).toInt() != 1)
        return tl::unexpected(vaultError(QStringLiteral("vault.meta_invalid"),
            QStringLiteral("保险库元数据无效或不受支持。"), parseError.errorString()));
    VaultMetadata metadata;
    metadata.version = 1;
    metadata.salt = QByteArray::fromBase64(object.value(QStringLiteral("salt")).toString().toLatin1());
    metadata.opsLimit = object.value(QStringLiteral("opsLimit")).toVariant().toULongLong();
    metadata.memLimit = object.value(QStringLiteral("memLimit")).toVariant().toULongLong();
    metadata.nonce = QByteArray::fromBase64(object.value(QStringLiteral("nonce")).toString().toLatin1());
    metadata.encryptedDatabaseKey = QByteArray::fromBase64(
        object.value(QStringLiteral("encryptedDatabaseKey")).toString().toLatin1());
    if (metadata.salt.size() != crypto_pwhash_SALTBYTES ||
        metadata.opsLimit < crypto_pwhash_OPSLIMIT_MIN ||
        metadata.opsLimit > crypto_pwhash_OPSLIMIT_SENSITIVE ||
        metadata.memLimit < crypto_pwhash_MEMLIMIT_MIN ||
        metadata.memLimit > crypto_pwhash_MEMLIMIT_SENSITIVE ||
        metadata.nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES ||
        metadata.encryptedDatabaseKey.size() != 32 + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        return tl::unexpected(vaultError(QStringLiteral("vault.meta_shape"),
            QStringLiteral("保险库元数据包含无效的加密参数。")));
    return metadata;
}

tl::expected<void, domain::AppError> SqlCipherVault::writeMetadata(const VaultMetadata &metadata) const
{
    QJsonObject object{
        {QStringLiteral("version"), metadata.version},
        {QStringLiteral("kdf"), QStringLiteral("argon2id13")},
        {QStringLiteral("cipher"), QStringLiteral("xchacha20poly1305")},
        {QStringLiteral("salt"), QString::fromLatin1(metadata.salt.toBase64())},
        {QStringLiteral("opsLimit"), QString::number(metadata.opsLimit)},
        {QStringLiteral("memLimit"), QString::number(metadata.memLimit)},
        {QStringLiteral("nonce"), QString::fromLatin1(metadata.nonce.toBase64())},
        {QStringLiteral("encryptedDatabaseKey"), QString::fromLatin1(metadata.encryptedDatabaseKey.toBase64())}
    };
    QSaveFile file(metadataPath());
    const QByteArray serialized = QJsonDocument(object).toJson(QJsonDocument::Indented);
    if (!file.open(QIODevice::WriteOnly) || file.write(serialized) != serialized.size() || !file.commit())
        return tl::unexpected(vaultError(QStringLiteral("vault.meta_write"),
            QStringLiteral("无法保存保险库元数据。"), file.errorString()));
    return {};
}

tl::expected<SecureBuffer, domain::AppError>
SqlCipherVault::deriveKek(const QByteArray &masterPassword, const VaultMetadata &metadata) const
{
    if (masterPassword.size() < 10)
        return tl::unexpected(vaultError(QStringLiteral("vault.password_short"),
            QStringLiteral("主密码必须至少包含 10 个字符。")));
    SecureBuffer kek(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    if (crypto_pwhash(kek.data(), static_cast<unsigned long long>(kek.size()),
                      masterPassword.constData(), static_cast<unsigned long long>(masterPassword.size()),
                      reinterpret_cast<const unsigned char *>(metadata.salt.constData()),
                      metadata.opsLimit, static_cast<size_t>(metadata.memLimit),
                      crypto_pwhash_ALG_ARGON2ID13) != 0)
        return tl::unexpected(vaultError(QStringLiteral("vault.kdf_memory"),
            QStringLiteral("没有足够的受保护内存来解锁保险库。")));
    return kek;
}

tl::expected<void, domain::AppError> SqlCipherVault::initialize(const QByteArray &masterPassword)
{
    if (!cryptoReady_)
        return tl::unexpected(vaultError(QStringLiteral("vault.crypto_init"),
            QStringLiteral("无法初始化本机加密运行库。")));
    if (exists()) return tl::unexpected(vaultError(QStringLiteral("vault.exists"),
        QStringLiteral("保险库已经初始化。")));
    if (!QDir().mkpath(directoryPath_)) return tl::unexpected(vaultError(QStringLiteral("vault.directory"),
        QStringLiteral("无法创建应用数据目录。"), directoryPath_));

    VaultMetadata metadata;
    metadata.salt.resize(crypto_pwhash_SALTBYTES);
    randombytes_buf(metadata.salt.data(), static_cast<size_t>(metadata.salt.size()));
    metadata.nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(metadata.nonce.data(), static_cast<size_t>(metadata.nonce.size()));
    SecureBuffer databaseKey(32);
    randombytes_buf(databaseKey.data(), static_cast<size_t>(databaseKey.size()));
    auto kek = deriveKek(masterPassword, metadata);
    if (!kek) return tl::unexpected(kek.error());
    metadata.encryptedDatabaseKey.resize(32 + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long cipherLength = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char *>(metadata.encryptedDatabaseKey.data()), &cipherLength,
        databaseKey.data(), static_cast<unsigned long long>(databaseKey.size()),
        reinterpret_cast<const unsigned char *>(kAad), sizeof(kAad) - 1, nullptr,
        reinterpret_cast<const unsigned char *>(metadata.nonce.constData()), kek->data());
    metadata.encryptedDatabaseKey.resize(static_cast<qsizetype>(cipherLength));
    if (auto result = writeMetadata(metadata); !result) return result;
    if (auto result = openDatabase(databaseKey, true); !result) {
        QFile::remove(metadataPath());
        QFile::remove(databasePath());
        return result;
    }
    databaseKey_ = std::move(databaseKey);
    return {};
}

tl::expected<void, domain::AppError> SqlCipherVault::unlock(const QByteArray &masterPassword)
{
    if (!cryptoReady_)
        return tl::unexpected(vaultError(QStringLiteral("vault.crypto_init"),
            QStringLiteral("无法初始化本机加密运行库。")));
    if (isUnlocked()) return {};
    auto metadata = readMetadata();
    if (!metadata) return tl::unexpected(metadata.error());
    auto kek = deriveKek(masterPassword, *metadata);
    if (!kek) return tl::unexpected(kek.error());
    SecureBuffer databaseKey(32);
    unsigned long long plainLength = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            databaseKey.data(), &plainLength, nullptr,
            reinterpret_cast<const unsigned char *>(metadata->encryptedDatabaseKey.constData()),
            static_cast<unsigned long long>(metadata->encryptedDatabaseKey.size()),
            reinterpret_cast<const unsigned char *>(kAad), sizeof(kAad) - 1,
            reinterpret_cast<const unsigned char *>(metadata->nonce.constData()), kek->data()) != 0)
        return tl::unexpected(vaultError(QStringLiteral("vault.password_invalid"),
            QStringLiteral("主密码不正确。")));
    if (plainLength != static_cast<unsigned long long>(databaseKey.size()))
        return tl::unexpected(vaultError(QStringLiteral("vault.database_key_shape"),
            QStringLiteral("保险库数据库密钥长度无效。")));
    if (auto result = openDatabase(databaseKey, false); !result) return result;
    databaseKey_ = std::move(databaseKey);
    return {};
}

tl::expected<void, domain::AppError>
SqlCipherVault::openDatabase(const SecureBuffer &databaseKey, const bool createSchema)
{
    lock();
    const int flags = SQLITE_OPEN_READWRITE | (createSchema ? SQLITE_OPEN_CREATE : 0) | SQLITE_OPEN_FULLMUTEX;
    const QByteArray path = QDir::toNativeSeparators(databasePath()).toUtf8();
    if (sqlite3_open_v2(path.constData(), &database_, flags, nullptr) != SQLITE_OK) {
        const QString details = database_ ? QString::fromUtf8(sqlite3_errmsg(database_)) : QString{};
        lock();
        return tl::unexpected(vaultError(QStringLiteral("vault.database_open"),
            QStringLiteral("无法打开加密数据库。"), details));
    }
    if (sqlite3_key(database_, databaseKey.data(), static_cast<int>(databaseKey.size())) != SQLITE_OK) {
        lock();
        return tl::unexpected(vaultError(QStringLiteral("vault.database_key"),
            QStringLiteral("SQLCipher 拒绝了数据库密钥。")));
    }
    if (auto result = execute("PRAGMA cipher_memory_security = ON; PRAGMA foreign_keys = ON;"); !result) {
        lock();
        return result;
    }
    if (!createSchema) {
        if (auto result = execute("SELECT count(*) FROM schema_version;"); !result) {
            lock();
            return tl::unexpected(vaultError(QStringLiteral("vault.database_invalid"),
                QStringLiteral("无法验证加密数据库。"), result.error().details));
        }
        int version = 0;
        {
            sqlite3_stmt *versionStatement = nullptr;
            if (sqlite3_prepare_v2(database_, "SELECT version FROM schema_version LIMIT 1;", -1,
                                   &versionStatement, nullptr) != SQLITE_OK) {
                lock();
                return tl::unexpected(vaultError(QStringLiteral("vault.schema_version"),
                    QStringLiteral("无法读取保险库架构版本。")));
            }
            const auto versionCleanup = qScopeGuard([&] { sqlite3_finalize(versionStatement); });
            if (sqlite3_step(versionStatement) != SQLITE_ROW) {
                const QString details = QString::fromUtf8(sqlite3_errmsg(database_));
                lock();
                return tl::unexpected(vaultError(QStringLiteral("vault.schema_version"),
                    QStringLiteral("保险库架构版本记录缺失。"), details));
            }
            version = sqlite3_column_int(versionStatement, 0);
        }
        if (version == 1) {
            if (auto result = execute(R"SQL(
BEGIN IMMEDIATE;
ALTER TABLE enrollment_requests ADD COLUMN friendly_name TEXT;
ALTER TABLE enrollment_requests ADD COLUMN requested_validity_days INTEGER NOT NULL DEFAULT 365;
ALTER TABLE enrollment_requests ADD COLUMN csr_text TEXT;
UPDATE schema_version SET version=2;
COMMIT;
)SQL"); !result) {
                lock();
                return result;
            }
        } else if (version != 2) {
            lock();
            return tl::unexpected(vaultError(QStringLiteral("vault.schema_unsupported"),
                QStringLiteral("保险库架构版本不受支持。"), QString::number(version)));
        }
        return {};
    }
    auto schemaResult = execute(R"SQL(
BEGIN IMMEDIATE;
CREATE TABLE schema_version (version INTEGER NOT NULL);
INSERT INTO schema_version VALUES (2);
CREATE TABLE settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL);
CREATE TABLE certificate_references (
    fingerprint_sha256 TEXT PRIMARY KEY, scope TEXT NOT NULL, store_role TEXT NOT NULL,
    friendly_name TEXT, tags_json TEXT NOT NULL DEFAULT '[]', notes TEXT
);
CREATE TABLE templates (
    id TEXT NOT NULL, version INTEGER NOT NULL, name TEXT NOT NULL, enabled INTEGER NOT NULL,
    schema_json TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (id, version)
);
CREATE TABLE enrollment_requests (
    id TEXT PRIMARY KEY, template_id TEXT NOT NULL, template_version INTEGER NOT NULL,
    scope TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, subject TEXT NOT NULL,
    csr_sha256 TEXT, public_key_sha256 TEXT, provider_name TEXT, key_container_name TEXT,
    state TEXT NOT NULL, remote_request_id TEXT, remote_ca TEXT, certificate_fingerprint TEXT,
    error_code TEXT, error_message TEXT, friendly_name TEXT,
    requested_validity_days INTEGER NOT NULL DEFAULT 365, csr_text TEXT
);
CREATE TABLE enrollment_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL, timestamp TEXT NOT NULL,
    from_state TEXT, to_state TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE ca_connections (
    id TEXT PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL, config_json TEXT NOT NULL, enabled INTEGER NOT NULL
);
CREATE TABLE trusted_ca_profiles (
    id TEXT PRIMARY KEY, fingerprint_sha256 TEXT NOT NULL, scope TEXT NOT NULL, metadata_json TEXT NOT NULL
);
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, action TEXT NOT NULL,
    target TEXT NOT NULL, scope TEXT NOT NULL, result TEXT NOT NULL, error TEXT
);
COMMIT;
)SQL");
    if (!schemaResult) lock();
    return schemaResult;
}

tl::expected<void, domain::AppError> SqlCipherVault::execute(const char *sql)
{
    char *error = nullptr;
    const int result = sqlite3_exec(database_, sql, nullptr, nullptr, &error);
    if (result == SQLITE_OK) return {};
    const QString details = error ? QString::fromUtf8(error) : QString::fromUtf8(sqlite3_errmsg(database_));
    if (error) sqlite3_free(error);
    return tl::unexpected(vaultError(QStringLiteral("vault.sql"),
        QStringLiteral("加密数据库操作失败。"), details));
}

void SqlCipherVault::lock()
{
    if (database_) sqlite3_close_v2(database_);
    database_ = nullptr;
    databaseKey_.clear();
}

tl::expected<void, domain::AppError> SqlCipherVault::append(const platform::AuditEvent &event)
{
    if (!database_) return tl::unexpected(vaultError(QStringLiteral("vault.locked"),
        QStringLiteral("写入审计日志前请先解锁保险库。")));
    constexpr auto sql = "INSERT INTO audit_events(timestamp,action,target,scope,result,error) VALUES(?,?,?,?,?,?);";
    sqlite3_stmt *statement = nullptr;
    if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK)
        return tl::unexpected(vaultError(QStringLiteral("vault.audit_prepare"),
            QStringLiteral("无法准备审计事件。"), QString::fromUtf8(sqlite3_errmsg(database_))));
    const auto cleanup = qScopeGuard([&] { sqlite3_finalize(statement); });
    const QList<QByteArray> values{event.timestamp.toUTC().toString(Qt::ISODateWithMs).toUtf8(),
        event.action.toUtf8(), event.target.toUtf8(), event.scope.toUtf8(), event.result.toUtf8(), event.error.toUtf8()};
    for (int i = 0; i < values.size(); ++i)
        sqlite3_bind_text(statement, i + 1, values[i].constData(), values[i].size(), SQLITE_TRANSIENT);
    if (sqlite3_step(statement) != SQLITE_DONE)
        return tl::unexpected(vaultError(QStringLiteral("vault.audit_write"),
            QStringLiteral("无法记录审计事件。"), QString::fromUtf8(sqlite3_errmsg(database_))));
    return {};
}

tl::expected<std::vector<platform::AuditEvent>, domain::AppError>
SqlCipherVault::auditEvents(const int limit) const
{
    if (!database_) return tl::unexpected(vaultError(QStringLiteral("vault.locked"),
        QStringLiteral("读取审计日志前请先解锁保险库。")));
    sqlite3_stmt *statement = nullptr;
    constexpr auto sql = R"SQL(
SELECT timestamp,action,target,scope,result,COALESCE(error,'')
FROM audit_events ORDER BY id DESC LIMIT ?;
)SQL";
    if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK)
        return tl::unexpected(vaultError(QStringLiteral("vault.audit_list"),
            QStringLiteral("无法读取审计日志。"), QString::fromUtf8(sqlite3_errmsg(database_))));
    const auto cleanup = qScopeGuard([&] { sqlite3_finalize(statement); });
    sqlite3_bind_int(statement, 1, std::clamp(limit, 1, 5000));
    std::vector<platform::AuditEvent> events;
    int stepResult = SQLITE_OK;
    while ((stepResult = sqlite3_step(statement)) == SQLITE_ROW) {
        events.push_back({QDateTime::fromString(columnText(statement, 0), Qt::ISODateWithMs),
            columnText(statement, 1), columnText(statement, 2), columnText(statement, 3),
            columnText(statement, 4), columnText(statement, 5)});
    }
    if (stepResult != SQLITE_DONE)
        return tl::unexpected(vaultError(QStringLiteral("vault.audit_read"),
            QStringLiteral("读取审计日志时数据库返回错误。"), QString::fromUtf8(sqlite3_errmsg(database_))));
    return events;
}

tl::expected<void, domain::AppError>
SqlCipherVault::saveEnrollmentRequest(const domain::EnrollmentRequest &request)
{
    if (!database_) return tl::unexpected(vaultError(QStringLiteral("vault.locked"),
        QStringLiteral("保存申请前请先解锁保险库。")));
    constexpr auto sql = R"SQL(
INSERT OR REPLACE INTO enrollment_requests(
 id,template_id,template_version,scope,created_at,updated_at,subject,csr_sha256,
 public_key_sha256,provider_name,key_container_name,state,remote_request_id,remote_ca,
 certificate_fingerprint,error_code,error_message,friendly_name,requested_validity_days,csr_text)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
)SQL";
    sqlite3_stmt *statement = nullptr;
    if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK)
        return tl::unexpected(vaultError(QStringLiteral("vault.request_prepare"),
            QStringLiteral("无法准备证书申请记录。"), QString::fromUtf8(sqlite3_errmsg(database_))));
    const auto cleanup = qScopeGuard([&] { sqlite3_finalize(statement); });
    const QList<QString> values{request.id, request.templateId, QString::number(request.templateVersion),
        QString::number(static_cast<int>(request.scope)), request.createdAt.toUTC().toString(Qt::ISODateWithMs),
        request.updatedAt.toUTC().toString(Qt::ISODateWithMs), request.subject, request.csrSha256,
        request.publicKeySha256, request.providerName, request.keyContainerName,
        domain::enrollmentStateName(request.state), request.remoteRequestId, request.remoteCA,
        request.certificateFingerprint, request.errorCode, request.errorMessage, request.friendlyName,
        QString::number(request.requestedValidityDays), request.csrText};
    for (int i = 0; i < values.size(); ++i) bindText(statement, i + 1, values[i]);
    if (sqlite3_step(statement) != SQLITE_DONE)
        return tl::unexpected(vaultError(QStringLiteral("vault.request_write"),
            QStringLiteral("无法保存证书申请。"), QString::fromUtf8(sqlite3_errmsg(database_))));
    return {};
}

tl::expected<std::vector<domain::EnrollmentRequest>, domain::AppError>
SqlCipherVault::enrollmentRequests() const
{
    if (!database_) return tl::unexpected(vaultError(QStringLiteral("vault.locked"),
        QStringLiteral("读取申请前请先解锁保险库。")));
    constexpr auto sql = R"SQL(
SELECT id,template_id,template_version,scope,created_at,updated_at,subject,csr_sha256,
 public_key_sha256,provider_name,key_container_name,state,remote_request_id,remote_ca,
 certificate_fingerprint,error_code,error_message,friendly_name,requested_validity_days,csr_text
FROM enrollment_requests ORDER BY created_at DESC;
)SQL";
    sqlite3_stmt *statement = nullptr;
    if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK)
        return tl::unexpected(vaultError(QStringLiteral("vault.request_list"),
            QStringLiteral("无法读取证书申请。"), QString::fromUtf8(sqlite3_errmsg(database_))));
    const auto cleanup = qScopeGuard([&] { sqlite3_finalize(statement); });
    std::vector<domain::EnrollmentRequest> records;
    int stepResult = SQLITE_OK;
    while ((stepResult = sqlite3_step(statement)) == SQLITE_ROW) {
        domain::EnrollmentRequest value;
        value.id = columnText(statement, 0);
        value.templateId = columnText(statement, 1);
        value.templateVersion = sqlite3_column_int(statement, 2);
        value.scope = static_cast<domain::StoreScope>(sqlite3_column_int(statement, 3));
        value.createdAt = QDateTime::fromString(columnText(statement, 4), Qt::ISODateWithMs);
        value.updatedAt = QDateTime::fromString(columnText(statement, 5), Qt::ISODateWithMs);
        value.subject = columnText(statement, 6);
        value.csrSha256 = columnText(statement, 7);
        value.publicKeySha256 = columnText(statement, 8);
        value.providerName = columnText(statement, 9);
        value.keyContainerName = columnText(statement, 10);
        value.state = enrollmentStateFromName(columnText(statement, 11));
        value.remoteRequestId = columnText(statement, 12);
        value.remoteCA = columnText(statement, 13);
        value.certificateFingerprint = columnText(statement, 14);
        value.errorCode = columnText(statement, 15);
        value.errorMessage = columnText(statement, 16);
        value.friendlyName = columnText(statement, 17);
        value.requestedValidityDays = sqlite3_column_int(statement, 18);
        value.csrText = columnText(statement, 19);
        records.emplace_back(std::move(value));
    }
    if (stepResult != SQLITE_DONE)
        return tl::unexpected(vaultError(QStringLiteral("vault.request_read"),
            QStringLiteral("读取证书申请时数据库返回错误。"), QString::fromUtf8(sqlite3_errmsg(database_))));
    return records;
}

tl::expected<void, domain::AppError> SqlCipherVault::saveManagedRoot(const ManagedRootRecord &record)
{
    if (!database_) return tl::unexpected(vaultError(QStringLiteral("vault.locked"), QStringLiteral("请先解锁保险库。")));
    constexpr auto sql = "INSERT OR REPLACE INTO certificate_references(fingerprint_sha256,scope,store_role,friendly_name,tags_json,notes) VALUES(?,?,?,?,'[]','APCM managed root');";
    sqlite3_stmt *statement = nullptr;
    if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK)
        return tl::unexpected(vaultError(QStringLiteral("vault.root_prepare"), QStringLiteral("无法准备托管根证书记录。")));
    const auto cleanup = qScopeGuard([&] { sqlite3_finalize(statement); });
    bindText(statement, 1, record.fingerprint); bindText(statement, 2, record.scope);
    bindText(statement, 3, record.storeRole); bindText(statement, 4, record.friendlyName);
    if (sqlite3_step(statement) != SQLITE_DONE)
        return tl::unexpected(vaultError(QStringLiteral("vault.root_write"), QStringLiteral("无法保存托管根证书。")));
    return {};
}

tl::expected<void, domain::AppError>
SqlCipherVault::saveManagedCertificate(const ManagedRootRecord &record)
{
    if (!database_) return tl::unexpected(vaultError(QStringLiteral("vault.locked"), QStringLiteral("请先解锁保险库。")));
    constexpr auto sql = "INSERT OR REPLACE INTO certificate_references(fingerprint_sha256,scope,store_role,friendly_name,tags_json,notes) VALUES(?,?,?,?,'[]','APCM installed certificate');";
    sqlite3_stmt *statement = nullptr;
    if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK)
        return tl::unexpected(vaultError(QStringLiteral("vault.certificate_prepare"), QStringLiteral("无法准备 APCM 证书管理记录。")));
    const auto cleanup = qScopeGuard([&] { sqlite3_finalize(statement); });
    bindText(statement, 1, record.fingerprint); bindText(statement, 2, record.scope);
    bindText(statement, 3, record.storeRole); bindText(statement, 4, record.friendlyName);
    if (sqlite3_step(statement) != SQLITE_DONE)
        return tl::unexpected(vaultError(QStringLiteral("vault.certificate_write"), QStringLiteral("无法保存 APCM 证书管理记录。")));
    return {};
}

tl::expected<void, domain::AppError> SqlCipherVault::removeManagedRoot(const QString &fingerprint)
{
    if (!database_) return tl::unexpected(vaultError(QStringLiteral("vault.locked"), QStringLiteral("请先解锁保险库。")));
    sqlite3_stmt *statement = nullptr;
    if (sqlite3_prepare_v2(database_, "DELETE FROM certificate_references WHERE fingerprint_sha256=? AND notes='APCM managed root';", -1, &statement, nullptr) != SQLITE_OK)
        return tl::unexpected(vaultError(QStringLiteral("vault.root_remove_prepare"), QStringLiteral("无法准备移除托管根证书。")));
    const auto cleanup = qScopeGuard([&] { sqlite3_finalize(statement); });
    bindText(statement, 1, fingerprint);
    if (sqlite3_step(statement) != SQLITE_DONE)
        return tl::unexpected(vaultError(QStringLiteral("vault.root_remove"), QStringLiteral("无法移除托管根证书。")));
    return {};
}

tl::expected<std::vector<SqlCipherVault::ManagedRootRecord>, domain::AppError>
SqlCipherVault::managedRoots() const
{
    if (!database_) return tl::unexpected(vaultError(QStringLiteral("vault.locked"), QStringLiteral("请先解锁保险库。")));
    sqlite3_stmt *statement = nullptr;
    constexpr auto sql = "SELECT fingerprint_sha256,scope,store_role,friendly_name FROM certificate_references WHERE notes='APCM managed root' ORDER BY friendly_name;";
    if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK)
        return tl::unexpected(vaultError(QStringLiteral("vault.root_list"), QStringLiteral("无法读取托管根证书。")));
    const auto cleanup = qScopeGuard([&] { sqlite3_finalize(statement); });
    std::vector<ManagedRootRecord> records;
    int stepResult = SQLITE_OK;
    while ((stepResult = sqlite3_step(statement)) == SQLITE_ROW)
        records.push_back({columnText(statement, 0), columnText(statement, 1), columnText(statement, 2), columnText(statement, 3)});
    if (stepResult != SQLITE_DONE)
        return tl::unexpected(vaultError(QStringLiteral("vault.root_read"),
            QStringLiteral("读取托管根证书时数据库返回错误。"), QString::fromUtf8(sqlite3_errmsg(database_))));
    return records;
}

tl::expected<std::vector<SqlCipherVault::ManagedRootRecord>, domain::AppError>
SqlCipherVault::managedCertificates() const
{
    if (!database_) return tl::unexpected(vaultError(QStringLiteral("vault.locked"), QStringLiteral("请先解锁保险库。")));
    sqlite3_stmt *statement = nullptr;
    constexpr auto sql = "SELECT fingerprint_sha256,scope,store_role,friendly_name FROM certificate_references WHERE notes IN ('APCM managed root','APCM installed certificate') ORDER BY friendly_name;";
    if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK)
        return tl::unexpected(vaultError(QStringLiteral("vault.certificate_list"), QStringLiteral("无法读取 APCM 证书管理清单。")));
    const auto cleanup = qScopeGuard([&] { sqlite3_finalize(statement); });
    std::vector<ManagedRootRecord> records;
    int stepResult = SQLITE_OK;
    while ((stepResult = sqlite3_step(statement)) == SQLITE_ROW)
        records.push_back({columnText(statement, 0), columnText(statement, 1), columnText(statement, 2), columnText(statement, 3)});
    if (stepResult != SQLITE_DONE)
        return tl::unexpected(vaultError(QStringLiteral("vault.certificate_read"),
            QStringLiteral("读取 APCM 证书管理清单时数据库返回错误。"), QString::fromUtf8(sqlite3_errmsg(database_))));
    return records;
}

tl::expected<void, domain::AppError> SqlCipherVault::saveConnection(const ConnectionRecord &record)
{
    if (!database_) return tl::unexpected(vaultError(QStringLiteral("vault.locked"), QStringLiteral("请先解锁保险库。")));
    const QJsonObject config{{QStringLiteral("endpoint"), record.endpoint}};
    sqlite3_stmt *statement = nullptr;
    constexpr auto sql = "INSERT OR REPLACE INTO ca_connections(id,type,name,config_json,enabled) VALUES(?,?,?,?,?);";
    if (sqlite3_prepare_v2(database_, sql, -1, &statement, nullptr) != SQLITE_OK)
        return tl::unexpected(vaultError(QStringLiteral("vault.connection_prepare"), QStringLiteral("无法准备 PKI 连接记录。")));
    const auto cleanup = qScopeGuard([&] { sqlite3_finalize(statement); });
    bindText(statement, 1, record.id); bindText(statement, 2, record.type); bindText(statement, 3, record.name);
    bindText(statement, 4, QString::fromUtf8(QJsonDocument(config).toJson(QJsonDocument::Compact)));
    sqlite3_bind_int(statement, 5, record.enabled ? 1 : 0);
    if (sqlite3_step(statement) != SQLITE_DONE)
        return tl::unexpected(vaultError(QStringLiteral("vault.connection_write"), QStringLiteral("无法保存 PKI 连接。")));
    return {};
}

tl::expected<void, domain::AppError> SqlCipherVault::removeConnection(const QString &id)
{
    if (!database_) return tl::unexpected(vaultError(QStringLiteral("vault.locked"), QStringLiteral("请先解锁保险库。")));
    sqlite3_stmt *statement = nullptr;
    if (sqlite3_prepare_v2(database_, "DELETE FROM ca_connections WHERE id=?;", -1, &statement, nullptr) != SQLITE_OK)
        return tl::unexpected(vaultError(QStringLiteral("vault.connection_remove_prepare"), QStringLiteral("无法准备删除 PKI 连接。")));
    const auto cleanup = qScopeGuard([&] { sqlite3_finalize(statement); });
    bindText(statement, 1, id);
    if (sqlite3_step(statement) != SQLITE_DONE)
        return tl::unexpected(vaultError(QStringLiteral("vault.connection_remove"), QStringLiteral("无法删除 PKI 连接。")));
    return {};
}

tl::expected<std::vector<SqlCipherVault::ConnectionRecord>, domain::AppError>
SqlCipherVault::connections() const
{
    if (!database_) return tl::unexpected(vaultError(QStringLiteral("vault.locked"), QStringLiteral("请先解锁保险库。")));
    sqlite3_stmt *statement = nullptr;
    if (sqlite3_prepare_v2(database_, "SELECT id,type,name,config_json,enabled FROM ca_connections ORDER BY name;", -1, &statement, nullptr) != SQLITE_OK)
        return tl::unexpected(vaultError(QStringLiteral("vault.connection_list"), QStringLiteral("无法读取 PKI 连接。")));
    const auto cleanup = qScopeGuard([&] { sqlite3_finalize(statement); });
    std::vector<ConnectionRecord> records;
    int stepResult = SQLITE_OK;
    while ((stepResult = sqlite3_step(statement)) == SQLITE_ROW) {
        const auto config = QJsonDocument::fromJson(columnText(statement, 3).toUtf8()).object();
        records.push_back({columnText(statement, 0), columnText(statement, 1), columnText(statement, 2),
                           config.value(QStringLiteral("endpoint")).toString(), sqlite3_column_int(statement, 4) != 0});
    }
    if (stepResult != SQLITE_DONE)
        return tl::unexpected(vaultError(QStringLiteral("vault.connection_read"),
            QStringLiteral("读取 PKI 连接时数据库返回错误。"), QString::fromUtf8(sqlite3_errmsg(database_))));
    return records;
}

} // namespace certmgr::persistence

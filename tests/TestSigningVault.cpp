#include "persistence/SqlCipherVault.h"
#include <QtTest>
#include <QFile>
#include <QJsonDocument>
#include <QScopeGuard>
#include <QTemporaryDir>
#include <sodium.h>
#include <sqlcipher/sqlite3.h>

extern "C" int sqlite3_key(sqlite3 *, const void *, int);

// An encrypted pre-v3 fixture, independent of SqlCipherVault's schema creation code.
static bool legacyFixture(const QString &directory, int version)
{
    QByteArray salt(crypto_pwhash_SALTBYTES, Qt::Uninitialized), key(32, Qt::Uninitialized), kek(32, Qt::Uninitialized);
    QByteArray nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, Qt::Uninitialized), sealed(48, Qt::Uninitialized);
    randombytes_buf(salt.data(), salt.size()); randombytes_buf(key.data(), key.size()); randombytes_buf(nonce.data(), nonce.size());
    if (crypto_pwhash(reinterpret_cast<unsigned char *>(kek.data()), kek.size(), "legacy password value", 21,
        reinterpret_cast<const unsigned char *>(salt.constData()), crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN, crypto_pwhash_ALG_ARGON2ID13) != 0) return false;
    const auto wipe = qScopeGuard([&] { sodium_memzero(key.data(), key.size()); sodium_memzero(kek.data(), kek.size()); });
    // Historic x64 vault builds authenticated the first seven bytes of the envelope label.
    unsigned long long sealedSize = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(reinterpret_cast<unsigned char *>(sealed.data()), &sealedSize,
        reinterpret_cast<const unsigned char *>(key.constData()), key.size(), reinterpret_cast<const unsigned char *>("certmgr"), 7,
        nullptr, reinterpret_cast<const unsigned char *>(nonce.constData()), reinterpret_cast<const unsigned char *>(kek.constData()));
    sealed.resize(static_cast<qsizetype>(sealedSize));
    QJsonObject metadata{{QStringLiteral("version"), 1}, {QStringLiteral("salt"), QString::fromLatin1(salt.toBase64())},
        {QStringLiteral("opsLimit"), QString::number(crypto_pwhash_OPSLIMIT_MIN)}, {QStringLiteral("memLimit"), QString::number(crypto_pwhash_MEMLIMIT_MIN)},
        {QStringLiteral("nonce"), QString::fromLatin1(nonce.toBase64())}, {QStringLiteral("encryptedDatabaseKey"), QString::fromLatin1(sealed.toBase64())}};
    QFile meta(directory + QStringLiteral("/vault.meta"));
    if (!meta.open(QIODevice::WriteOnly) || meta.write(QJsonDocument(metadata).toJson()) <= 0) return false;
    meta.close();
    sqlite3 *database = nullptr;
    if (sqlite3_open((directory + QStringLiteral("/vault.db")).toUtf8().constData(), &database) != SQLITE_OK) return false;
    const auto close = qScopeGuard([&] { sqlite3_close(database); });
    if (sqlite3_key(database, key.constData(), key.size()) != SQLITE_OK) return false;
    QByteArray schema = R"SQL(
CREATE TABLE schema_version(version INTEGER NOT NULL);
CREATE TABLE enrollment_requests (
 id TEXT PRIMARY KEY,template_id TEXT NOT NULL,template_version INTEGER NOT NULL,scope TEXT NOT NULL,
 created_at TEXT NOT NULL,updated_at TEXT NOT NULL,subject TEXT NOT NULL,csr_sha256 TEXT,public_key_sha256 TEXT,
 provider_name TEXT,key_container_name TEXT,state TEXT NOT NULL,remote_request_id TEXT,remote_ca TEXT,
 certificate_fingerprint TEXT,error_code TEXT,error_message TEXT
);
CREATE TABLE ca_connections(id TEXT PRIMARY KEY,type TEXT,name TEXT,config_json TEXT,enabled INTEGER);
INSERT INTO ca_connections VALUES('old-connection','manual','Old CA','{}',1);
INSERT INTO enrollment_requests(id,template_id,template_version,scope,created_at,updated_at,subject,state,remote_request_id,remote_ca)
 VALUES('legacy-request','template',1,'0','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z','CN=legacy','SUBMITTED','remote-id','Legacy CA');
CREATE TABLE audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT,action TEXT,target TEXT,scope TEXT,result TEXT,error TEXT);
INSERT INTO audit_events(timestamp,action,target,scope,result) VALUES('2026-01-01T00:00:00Z','SAVE_CONNECTION','old-connection','local','SUCCESS');
)SQL";
    schema += "INSERT INTO schema_version VALUES(" + QByteArray::number(version) + ");";
    if (version == 2) schema += "ALTER TABLE enrollment_requests ADD COLUMN friendly_name TEXT; ALTER TABLE enrollment_requests ADD COLUMN requested_validity_days INTEGER NOT NULL DEFAULT 365; ALTER TABLE enrollment_requests ADD COLUMN csr_text TEXT;";
    return sqlite3_exec(database, schema.constData(), nullptr, nullptr, nullptr) == SQLITE_OK;
}
class TestSigningVault final : public QObject {
    Q_OBJECT
private slots:
    void initTestCase() { QVERIFY(sodium_init() >= 0); }
    void preparedBytesAndRevocationIntentSurviveRestart() {
        QTemporaryDir dir; QVERIFY(dir.isValid());
        certmgr::persistence::SqlCipherVault vault(dir.path());
        QVERIFY(vault.initialize("correct horse battery staple"));
        const QByteArray bytes("{ \"csr_pem\" : \"PUBLIC-CSR-FIXTURE\\n\", \"validity_seconds\": 0 }\n");
        const QJsonObject record{{QStringLiteral("id"), QStringLiteral("operation-fixture")},
            {QStringLiteral("state"), QStringLiteral("UNCERTAIN")}, {QStringLiteral("idempotencyKey"), QStringLiteral("persisted-key-fixture")},
            {QStringLiteral("requestBodyBase64"), QString::fromLatin1(bytes.toBase64())},
            {QStringLiteral("credentialDigest"), QString(64, 'a')}, {QStringLiteral("pendingRevokeReason"), 1}};
        QVERIFY(vault.saveSigningRecord(QStringLiteral("operation"), QStringLiteral("operation-fixture"), record));
        vault.lock();
        QVERIFY(!vault.signingRecords(QStringLiteral("operation")));
        QVERIFY(vault.unlock("correct horse battery staple"));
        auto loaded = vault.signingRecords(QStringLiteral("operation")); QVERIFY(loaded); QCOMPARE(loaded->size(), 1);
        const auto stored = loaded->front().toMap();
        QCOMPARE(QByteArray::fromBase64(stored.value(QStringLiteral("requestBodyBase64")).toString().toLatin1()), bytes);
        QCOMPARE(stored.value(QStringLiteral("idempotencyKey")).toString(), QStringLiteral("persisted-key-fixture"));
        QCOMPARE(stored.value(QStringLiteral("pendingRevokeReason")).toInt(), 1);
        QFile encrypted(vault.databasePath()); QVERIFY(encrypted.open(QIODevice::ReadOnly));
        const auto raw = encrypted.readAll(); QVERIFY(!raw.contains("persisted-key-fixture")); QVERIFY(!raw.contains("PUBLIC-CSR-FIXTURE"));
        QVERIFY(vault.removeSigningRecord(QStringLiteral("operation"), QStringLiteral("operation-fixture")));
        loaded = vault.signingRecords(QStringLiteral("operation")); QVERIFY(loaded); QVERIFY(loaded->isEmpty());
    }
    void migratesOldVaultWithoutLosingRequestsOrAudit_data() {
        QTest::addColumn<int>("version"); QTest::newRow("v1") << 1; QTest::newRow("v2") << 2;
    }
    void migratesOldVaultWithoutLosingRequestsOrAudit() {
        QFETCH(int, version);
        QTemporaryDir dir; QVERIFY(dir.isValid()); QVERIFY(legacyFixture(dir.path(), version));
        certmgr::persistence::SqlCipherVault vault(dir.path());
        auto opened = vault.unlock("legacy password value"); QVERIFY2(opened, opened ? "" : qPrintable(opened.error().message));
        const auto requests = vault.enrollmentRequests(); QVERIFY(requests); QCOMPARE(requests->size(), size_t(1));
        QCOMPARE(requests->front().remoteRequestId, QStringLiteral("remote-id")); QCOMPARE(requests->front().remoteCA, QStringLiteral("Legacy CA"));
        const auto audit = vault.auditEvents(); QVERIFY(audit); QCOMPARE(audit->size(), size_t(1)); QCOMPARE(audit->front().action, QStringLiteral("SAVE_CONNECTION"));
        QVERIFY(vault.saveSigningRecord(QStringLiteral("operation"), QStringLiteral("new-operation"), {{QStringLiteral("id"), QStringLiteral("new-operation")}}));
        vault.lock(); QVERIFY(vault.unlock("legacy password value"));
        auto records = vault.signingRecords(QStringLiteral("operation")); QVERIFY(records); QCOMPARE(records->size(), 1);
    }
    void lockedVaultRejectsSigningWrites() {
        QTemporaryDir dir; certmgr::persistence::SqlCipherVault vault(dir.path());
        QVERIFY(!vault.saveSigningRecord(QStringLiteral("operation"), QStringLiteral("id"), {}));
        QVERIFY(!vault.signingRecords(QStringLiteral("profile")));
        QVERIFY(!vault.removeSigningRecord(QStringLiteral("profile"), QStringLiteral("id")));
    }
};
QTEST_GUILESS_MAIN(TestSigningVault)
#include "TestSigningVault.moc"

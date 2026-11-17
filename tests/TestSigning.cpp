#include "domain/signing/SigningProtocol.h"
#include "services/SigningHttpClient.h"
#include <QtTest>
#include <QFile>
#include <QJsonDocument>
#include <QNetworkCookieJar>
#include <QSslKey>
#include <QSslSocket>
#include <QTcpServer>
#include <QTemporaryDir>
#include <QTimer>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#include <memory>
#include <ctime>

using namespace certmgr::domain::signing;
using certmgr::services::SigningHttpClient;
using certmgr::services::SigningHttpResult;
namespace {
template<class T, auto Free> using Ptr = std::unique_ptr<T, decltype(Free)>;
using Key = Ptr<EVP_PKEY, EVP_PKEY_free>;
using Cert = Ptr<X509, X509_free>;
using Request = Ptr<X509_REQ, X509_REQ_free>;
using Bio = Ptr<BIO, BIO_free>;
const QString instanceId = QStringLiteral("00000000-0000-4000-8000-000000000001");
const QByteArray token("ist_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG");

Key makeKey(const char *curve = "prime256v1")
{
    Ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_free> context(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY_keygen_init(context.get()); EVP_PKEY_CTX_set_group_name(context.get(), curve);
    EVP_PKEY *key = nullptr; EVP_PKEY_generate(context.get(), &key);
    return Key(key, EVP_PKEY_free);
}
QByteArray bioBytes(BIO *bio)
{
    char *data = nullptr; const long size = BIO_get_mem_data(bio, &data);
    return QByteArray(data, static_cast<qsizetype>(size));
}
QByteArray pemKey(EVP_PKEY *key)
{
    Bio out(BIO_new(BIO_s_mem()), BIO_free); PEM_write_bio_PrivateKey(out.get(), key, nullptr, nullptr, 0, nullptr, nullptr); return bioBytes(out.get());
}
QByteArray pemCert(X509 *cert)
{
    Bio out(BIO_new(BIO_s_mem()), BIO_free); PEM_write_bio_X509(out.get(), cert); return bioBytes(out.get());
}
QByteArray derCert(X509 *cert)
{
    Bio out(BIO_new(BIO_s_mem()), BIO_free); i2d_X509_bio(out.get(), cert); return bioBytes(out.get());
}
void extension(X509 *cert, X509 *issuer, const int nid, const char *value)
{
    X509V3_CTX context{}; X509V3_set_ctx(&context, issuer ? issuer : cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &context, nid, const_cast<char *>(value));
    Q_ASSERT(ext); X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext);
}
Cert makeCert(EVP_PKEY *key, X509 *issuer, EVP_PKEY *issuerKey, const bool ca, const bool client = false)
{
    Cert cert(X509_new(), X509_free);
    X509_set_version(cert.get(), 2); ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), ca ? 1 : client ? 3 : 2);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60); X509_gmtime_adj(X509_getm_notAfter(cert.get()), 86400);
    X509_set_pubkey(cert.get(), key);
    X509_NAME *name = X509_get_subject_name(cert.get());
    const QByteArray cn = ca ? QByteArray("Test Root") : QByteArray("localhost");
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>(cn.constData()), -1, -1, 0);
    X509_set_issuer_name(cert.get(), issuer ? X509_get_subject_name(issuer) : name);
    extension(cert.get(), issuer, NID_basic_constraints, ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    extension(cert.get(), issuer, NID_key_usage, ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature");
    extension(cert.get(), issuer, NID_subject_key_identifier, "hash");
    if (!ca) {
        extension(cert.get(), issuer, NID_subject_alt_name, "DNS:localhost");
        extension(cert.get(), issuer, NID_ext_key_usage, client ? "clientAuth" : "serverAuth");
    }
    X509_sign(cert.get(), issuerKey ? issuerKey : key, EVP_sha256());
    return cert;
}
QByteArray makeCsr(EVP_PKEY *key, const QByteArray &san = "DNS:localhost", const QByteArray &cn = "localhost", const bool extra = false)
{
    Request request(X509_REQ_new(), X509_REQ_free);
    X509_REQ_set_version(request.get(), 0); X509_REQ_set_pubkey(request.get(), key);
    X509_NAME_add_entry_by_txt(X509_REQ_get_subject_name(request.get()), "CN", MBSTRING_UTF8,
        reinterpret_cast<const unsigned char *>(cn.constData()), cn.size(), -1, 0);
    auto *extensions = sk_X509_EXTENSION_new_null();
    if (!san.isEmpty()) sk_X509_EXTENSION_push(extensions, X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, const_cast<char *>(san.constData())));
    if (extra) sk_X509_EXTENSION_push(extensions, X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage, const_cast<char *>("digitalSignature")));
    X509_REQ_add_extensions(request.get(), extensions); sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    X509_REQ_sign(request.get(), key, EVP_sha256());
    Bio output(BIO_new(BIO_s_mem()), BIO_free); PEM_write_bio_X509_REQ(output.get(), request.get()); return bioBytes(output.get());
}
QJsonObject record(X509 *leaf, X509 *root)
{
    const QSslCertificate qt(derCert(leaf), QSsl::Der);
    return {{QStringLiteral("id"), QStringLiteral("00000000-0000-4000-8000-000000000101")},
        {QStringLiteral("instance_id"), instanceId}, {QStringLiteral("credential_id"), QStringLiteral("00000000-0000-4000-8000-000000000011")},
        {QStringLiteral("serial"), QStringLiteral("2")}, {QStringLiteral("certificate_pem"), QString::fromUtf8(pemCert(leaf))},
        {QStringLiteral("chain_pem"), QString::fromUtf8(pemCert(leaf) + pemCert(root))},
        {QStringLiteral("fingerprint_sha256"), fingerprint(derCert(leaf))}, {QStringLiteral("status"), QStringLiteral("good")},
        {QStringLiteral("revoked_at"), QJsonValue::Null}, {QStringLiteral("revocation_reason"), QJsonValue::Null},
        {QStringLiteral("not_before"), qt.effectiveDate().toUTC().toString(Qt::ISODate)},
        {QStringLiteral("not_after"), qt.expiryDate().toUTC().toString(Qt::ISODate)}};
}
class TlsServer : public QTcpServer {
public:
    QSslConfiguration config;
    QList<QByteArray> requests;
    QByteArray response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
    void incomingConnection(qintptr descriptor) override
    {
        auto *socket = new QSslSocket(this); socket->setSslConfiguration(config); socket->setSocketDescriptor(descriptor);
        auto bytes = std::make_shared<QByteArray>(); auto answered = std::make_shared<bool>(false);
        QObject::connect(socket, &QIODevice::readyRead, socket, [this, socket, bytes, answered] {
            bytes->append(socket->readAll());
            const auto end = bytes->indexOf("\r\n\r\n"); if (end < 0 || *answered) return;
            const auto header = bytes->left(end);
            qsizetype length = 0;
            for (const auto &line : header.split('\n')) if (line.toLower().startsWith("content-length:")) length = line.mid(15).trimmed().toLongLong();
            if (bytes->size() < end + 4 + length) return;
            *answered = true; requests.append(*bytes); socket->write(response); socket->disconnectFromHost();
        });
        QObject::connect(socket, &QAbstractSocket::disconnected, socket, &QObject::deleteLater);
        socket->startServerEncryption();
    }
};
}
class TestSigning final : public QObject {
    Q_OBJECT
    Key rootKey{nullptr, EVP_PKEY_free}, leafKey{nullptr, EVP_PKEY_free}, clientKey{nullptr, EVP_PKEY_free};
    Cert root{nullptr, X509_free}, leaf{nullptr, X509_free}, client{nullptr, X509_free};
    QByteArray csr;
    QSslConfiguration clientTls() const {
        auto config = QSslConfiguration::defaultConfiguration(); config.addCaCertificate(QSslCertificate(derCert(root.get()), QSsl::Der)); return config;
    }
    void setup(TlsServer &server, bool requireClient = false) {
        server.config = QSslConfiguration::defaultConfiguration();
        server.config.setLocalCertificate(QSslCertificate(derCert(leaf.get()), QSsl::Der));
        server.config.setPrivateKey(QSslKey(pemKey(leafKey.get()), QSsl::Ec));
        server.config.setCaCertificates({QSslCertificate(derCert(root.get()), QSsl::Der)});
        server.config.setPeerVerifyMode(requireClient ? QSslSocket::VerifyPeer : QSslSocket::VerifyNone);
        QVERIFY(server.listen(QHostAddress::LocalHost));
    }
    QUrl url(const TlsServer &server) const { return QUrl(QStringLiteral("https://localhost:%1/signing/%2/issue").arg(server.serverPort()).arg(instanceId)); }
private slots:
    void initTestCase() {
        QVERIFY(QSslSocket::supportsSsl());
        qInfo().noquote() << "TLS backend:" << QSslSocket::activeBackend()
                          << "runtime:" << QSslSocket::sslLibraryVersionString();
        rootKey = makeKey(); leafKey = makeKey(); clientKey = makeKey();
        QVERIFY(rootKey && leafKey && clientKey);
        root = makeCert(rootKey.get(), nullptr, nullptr, true);
        leaf = makeCert(leafKey.get(), root.get(), rootKey.get(), false);
        client = makeCert(clientKey.get(), root.get(), rootKey.get(), false, true);
        csr = makeCsr(leafKey.get());
    }
    void strictEndpointsAndToken() {
        QVERIFY(issueEndpoint(QStringLiteral("https://pki.example.com/signing/") + instanceId + QStringLiteral("/issue")));
        for (const auto &invalid : {QStringLiteral("http://pki.example.com/signing/") + instanceId + QStringLiteral("/issue"),
             QStringLiteral("https://user@pki.example.com/signing/") + instanceId + QStringLiteral("/issue"),
             QStringLiteral("https://pki.example.com/signing/") + instanceId + QStringLiteral("/issue?token=secret"),
             QStringLiteral("https://pki.example.com/signing/not-a-uuid/issue")}) QVERIFY(!issueEndpoint(invalid));
        QVERIFY(consoleEndpoint(QStringLiteral("https://console.example.com/api/v1")));
        QVERIFY(!consoleEndpoint(QStringLiteral("https://console.example.com/api/v1/")));
        QVERIFY(validToken(token)); QVERIFY(!validToken(token + "\n"));
        QVERIFY(validReason(0)); QVERIFY(validReason(10)); QVERIFY(!validReason(7)); QVERIFY(!validReason(8));
    }
    void csrRejectsExtraExtensionsAndMissingSan() {
        QVERIFY(inspectCsr(csr));
        QVERIFY(!inspectCsr(makeCsr(leafKey.get(), "DNS:localhost", "localhost", true)));
        QVERIFY(!inspectCsr(makeCsr(leafKey.get(), {}, "localhost")));
        QVERIFY(!inspectCsr(csr + csr));
        QVERIFY(!inspectCsr(csr + pemKey(leafKey.get())));
    }
    void csrRejectsCnMismatchUnsupportedCurveAndOtherName() {
        QVERIFY(!inspectCsr(makeCsr(leafKey.get(), "DNS:localhost", "database")));
        auto unsupported = makeKey("secp521r1");
        QVERIFY(!inspectCsr(makeCsr(unsupported.get())));
        QVERIFY(!inspectCsr(makeCsr(leafKey.get(), "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:localhost")));
        QVERIFY(inspectCsr(makeCsr(leafKey.get(), "email:service@example.com,URI:spiffe://example.com/workloads/db", "service@example.com")));
    }
    void responseVerifiesKeySanFingerprintSerialAndPurpose() {
        const auto good = record(leaf.get(), root.get());
        auto checked = inspectCertificate(good, csr, {QStringLiteral("server_auth")}, pemCert(root.get()));
        QVERIFY2(checked, qPrintable(checked ? QString{} : checked.error().message));
        QVERIFY(checked->value(QStringLiteral("installable")).toBool());
        auto changed = good; changed[QStringLiteral("serial")] = QStringLiteral("3"); QVERIFY(!inspectCertificate(changed, csr, {}, pemCert(root.get())));
        changed = good; changed[QStringLiteral("fingerprint_sha256")] = QString(64, '0'); QVERIFY(!inspectCertificate(changed, csr, {}, pemCert(root.get())));
        QVERIFY(!inspectCertificate(good, makeCsr(clientKey.get()), {}, pemCert(root.get())));
        QVERIFY(!inspectCertificate(good, csr, {QStringLiteral("client_auth")}, pemCert(root.get())));
    }
    void downloadedRootDoesNotBecomeTrustedAndHistoricalCannotInstall() {
        const auto good = record(leaf.get(), root.get());
        auto checked = inspectCertificate(good, csr, {}, {}); QVERIFY(checked); QVERIFY(!checked->value(QStringLiteral("chainTrusted")).toBool());
        QVERIFY(!checked->value(QStringLiteral("installable")).toBool());
        auto revoked = good; revoked[QStringLiteral("status")] = QStringLiteral("revoked");
        revoked[QStringLiteral("revoked_at")] = QDateTime::currentDateTimeUtc().toString(Qt::ISODate); revoked[QStringLiteral("revocation_reason")] = 1;
        checked = inspectCertificate(revoked, csr, {}, pemCert(root.get())); QVERIFY(checked); QVERIFY(!checked->value(QStringLiteral("installable")).toBool());
        checked = inspectCertificate(good, {}, {}, pemCert(root.get())); QVERIFY(checked); QVERIFY(!checked->value(QStringLiteral("installable")).toBool());
        QVERIFY(inspectIssuer(derCert(root.get()))); QVERIFY(!inspectIssuer(pemCert(root.get())));
    }
    void loadsPfxAndPemTransportIdentityWithoutPromotingIssuerToTrust() {
        QTemporaryDir directory; QVERIFY(directory.isValid());
        const QString pfx = directory.filePath(QStringLiteral("client.pfx"));
        Ptr<PKCS12, PKCS12_free> bundle(PKCS12_create("password", "client", clientKey.get(), client.get(), nullptr, 0, 0, 0, 0, 0), PKCS12_free);
        Bio output(BIO_new(BIO_s_mem()), BIO_free); QVERIFY(i2d_PKCS12_bio(output.get(), bundle.get()));
        QFile file(pfx); QVERIFY(file.open(QIODevice::WriteOnly)); file.write(bioBytes(output.get())); file.close();
        QVariantMap options{{QStringLiteral("clientCertificateFile"), QUrl::fromLocalFile(pfx).toString()}};
        auto tls = transportConfiguration(options, "wrong", true); QVERIFY(!tls);
        tls = transportConfiguration(options, "password", true); QVERIFY(tls); QVERIFY(!tls->privateKey().isNull());
        QVERIFY(!tls->caCertificates().contains(QSslCertificate(derCert(client.get()), QSsl::Der)));
        auto unloaded = transportConfiguration(options, {}, false); QVERIFY(unloaded); QVERIFY(unloaded->privateKey().isNull());
        const QString certPath = directory.filePath(QStringLiteral("client.pem")); const QString keyPath = directory.filePath(QStringLiteral("client.key"));
        QFile certFile(certPath); QVERIFY(certFile.open(QIODevice::WriteOnly)); certFile.write(pemCert(client.get())); certFile.close();
        QFile keyFile(keyPath); QVERIFY(keyFile.open(QIODevice::WriteOnly)); keyFile.write(pemKey(clientKey.get())); keyFile.close();
        options[QStringLiteral("clientCertificateFile")] = QUrl::fromLocalFile(certPath).toString(); options[QStringLiteral("clientKeyFile")] = QUrl::fromLocalFile(keyPath).toString();
        tls = transportConfiguration(options, {}, true); QVERIFY(tls); QVERIFY(!tls->localCertificate().isNull());
    }
    void crlRequiresSignatureFreshnessAndMatchingCriticalIdp() {
        Ptr<X509_CRL, X509_CRL_free> crl(X509_CRL_new(), X509_CRL_free);
        X509_CRL_set_version(crl.get(), 1); X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(root.get()));
        Ptr<ASN1_TIME, ASN1_TIME_free> start(ASN1_TIME_adj(nullptr, time(nullptr), 0, -60), ASN1_TIME_free);
        Ptr<ASN1_TIME, ASN1_TIME_free> end(ASN1_TIME_adj(nullptr, time(nullptr), 1, 0), ASN1_TIME_free);
        X509_CRL_set1_lastUpdate(crl.get(), start.get()); X509_CRL_set1_nextUpdate(crl.get(), end.get());
        Ptr<ISSUING_DIST_POINT, ISSUING_DIST_POINT_free> idp(ISSUING_DIST_POINT_new(), ISSUING_DIST_POINT_free);
        idp->onlyuser = 0xff; idp->distpoint = DIST_POINT_NAME_new(); idp->distpoint->type = 0;
        idp->distpoint->name.fullname = sk_GENERAL_NAME_new_null();
        auto *name = GENERAL_NAME_new(); name->type = GEN_URI; name->d.uniformResourceIdentifier = ASN1_IA5STRING_new();
        const QByteArray location = "https://pki.example.com/signing/" + instanceId.toLatin1() + "/crl";
        ASN1_STRING_set(name->d.uniformResourceIdentifier, location.constData(), location.size());
        sk_GENERAL_NAME_push(idp->distpoint->name.fullname, name);
        QVERIFY(X509_CRL_add1_ext_i2d(crl.get(), NID_issuing_distribution_point, idp.get(), 1, X509V3_ADD_DEFAULT));
        QVERIFY(X509_CRL_sign(crl.get(), rootKey.get(), EVP_sha256()));
        Bio out(BIO_new(BIO_s_mem()), BIO_free); i2d_X509_CRL_bio(out.get(), crl.get());
        const QUrl endpoint(QStringLiteral("https://pki.example.com/signing/") + instanceId + QStringLiteral("/issue"));
        QVERIFY(inspectCrl(bioBytes(out.get()), derCert(root.get()), endpoint));
        QVERIFY(!inspectCrl(bioBytes(out.get()), derCert(leaf.get()), endpoint));
        QVERIFY(!inspectCrl(bioBytes(out.get()), derCert(root.get()), QUrl(QStringLiteral("https://other.example.com/signing/") + instanceId + QStringLiteral("/issue"))));
        X509_CRL_set1_nextUpdate(crl.get(), start.get()); X509_CRL_sign(crl.get(), rootKey.get(), EVP_sha256());
        BIO_reset(out.get()); i2d_X509_CRL_bio(out.get(), crl.get());
        QVERIFY(!inspectCrl(bioBytes(out.get()), derCert(root.get()), endpoint));
    }
    void missingMtlsIsReportedAndConfiguredIdentityWorks() {
        TlsServer server; setup(server, true);
        SigningHttpClient http(false); QVariantMap settings{{QStringLiteral("mtlsRequired"), true}};
        QVERIFY(http.configure(url(server), settings, clientTls()));
        bool done = false; SigningHttpResult response;
        http.send("GET", url(server), {}, {}, {}, {}, 200, [&](auto r) { response = r; done = true; });
        QVERIFY(done); QCOMPARE(response.problemCode, QStringLiteral("mtls_required")); QVERIFY(server.requests.isEmpty());
        // Without a predeclared requirement, a real missing-certificate handshake still gives an mTLS hint.
        settings[QStringLiteral("mtlsRequired")] = false;
        QVERIFY(http.configure(url(server), settings, clientTls())); done = false;
        http.send("GET", url(server), {}, {}, {}, {}, 200, [&](auto r) { response = r; done = true; });
        QTRY_VERIFY_WITH_TIMEOUT(done, 5000); QVERIFY(!response.ok); QVERIFY(response.error.contains(QStringLiteral("mTLS"))); QVERIFY(server.requests.isEmpty());
        // Exercise an actual mandatory-client-certificate TLS handshake with the correct identity.
        settings[QStringLiteral("mtlsRequired")] = true;
        auto tls = clientTls(); tls.setLocalCertificate(QSslCertificate(derCert(client.get()), QSsl::Der)); tls.setPrivateKey(QSslKey(pemKey(clientKey.get()), QSsl::Ec));
        QVERIFY(http.configure(url(server), settings, tls)); done = false;
        http.send("GET", url(server), {}, {}, {}, {}, 200, [&](auto r) { response = r; done = true; });
        QTRY_VERIFY_WITH_TIMEOUT(done, 5000); QVERIFY2(response.ok, qPrintable(response.error)); QCOMPARE(server.requests.size(), 1);
    }
    void untrustedServersAndWrongHostnamesReceiveNoBearer() {
        TlsServer server; setup(server); SigningHttpClient http(false);
        for (int i = 0; i < 2; ++i) {
            QUrl target = url(server);
            auto tls = i == 0 ? QSslConfiguration::defaultConfiguration() : clientTls();
            if (i == 1) target.setHost(QStringLiteral("127.0.0.1"));
            QVERIFY(http.configure(target, {}, tls));
            bool done = false; SigningHttpResult response;
            http.send("POST", target, "{}", token, {}, "operation-key", 201, [&](auto r) { response = r; done = true; });
            QTRY_VERIFY_WITH_TIMEOUT(done, 5000); QVERIFY(!response.ok); QVERIFY(server.requests.isEmpty());
        }
    }
    void loginFailuresDoNotReflectPasswords() {
        TlsServer server; setup(server);
        const QByteArray body = QJsonDocument(QJsonObject{{QStringLiteral("detail"), QStringLiteral("secret-password-for-test")}, {QStringLiteral("code"), QStringLiteral("login_failed")}}).toJson(QJsonDocument::Compact);
        server.response = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/problem+json\r\nContent-Length: " + QByteArray::number(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        SigningHttpClient http(true); QVERIFY(http.configure(url(server), {}, clientTls()));
        QUrl login = url(server); login.setPath(QStringLiteral("/api/v1/auth/login"));
        bool done = false; SigningHttpResult response;
        http.send("POST", login, "{\"login\":\"user\",\"password\":\"secret-password-for-test\"}", {}, {}, {}, 200, [&](auto r) { response = r; done = true; });
        QTRY_VERIFY_WITH_TIMEOUT(done, 5000); QVERIFY(!response.ok); QVERIFY(!response.error.contains(QStringLiteral("secret-password-for-test")));
        QVERIFY(!response.error.contains(QStringLiteral("原签发 Token")));
    }
    void nginxMissingClientCertificateIsDistinctFromToken401() {
        TlsServer server; setup(server);
        server.response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nContent-Length: 36\r\nConnection: close\r\n\r\nNo required SSL certificate was sent!";
        SigningHttpClient http(false); QVERIFY(http.configure(url(server), {}, clientTls()));
        bool done = false; SigningHttpResult response;
        http.send("GET", url(server), {}, {}, {}, {}, 200, [&](auto r) { response = r; done = true; });
        QTRY_VERIFY_WITH_TIMEOUT(done, 5000); QCOMPARE(response.problemCode, QStringLiteral("mtls_required"));
        QVERIFY(!safeProblem(401, {}, {}).contains(QStringLiteral("mTLS")));
    }
    void redirectsAreBlockedAndCredentialsNeverCrossOrigins() {
        TlsServer server; setup(server);
        server.response = "HTTP/1.1 302 Found\r\nLocation: https://attacker.example/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        SigningHttpClient http(false); QVERIFY(http.configure(url(server), {}, clientTls()));
        bool done = false; SigningHttpResult response;
        http.send("POST", url(server), "{}", token, {}, "test-operation-key", 201, [&](auto r) { response = r; done = true; });
        QTRY_VERIFY_WITH_TIMEOUT(done, 5000); QCOMPARE(response.problemCode, QStringLiteral("redirect_blocked")); QCOMPARE(server.requests.size(), 1);
        done = false; QUrl other = url(server); other.setHost(QStringLiteral("attacker.example"));
        http.send("POST", other, "{}", token, {}, "test-operation-key", 201, [&](auto r) { response = r; done = true; });
        QVERIFY(done); QVERIFY(!response.ok); QCOMPARE(server.requests.size(), 1);
    }
    void exactBytesAndIdempotencyKeySurviveRetries() {
        TlsServer server; setup(server);
        server.response.replace("200 OK", "201 Created");
        SigningHttpClient http(false); QVERIFY(http.configure(url(server), {}, clientTls()));
        const QByteArray body("{ \"csr_pem\" : \"line1\\nline2\", \"validity_seconds\": 0 }\n");
        for (int i = 0; i < 2; ++i) {
            bool done = false;
            http.send("POST", url(server), body, token, {}, "persisted-operation-key", 201, [&](auto r) { QVERIFY(r.ok); done = true; });
            QTRY_VERIFY_WITH_TIMEOUT(done, 5000);
        }
        QCOMPARE(server.requests.size(), 2);
        for (const auto &request : server.requests) { QVERIFY(request.endsWith(body)); QVERIFY(request.contains("Idempotency-Key: persisted-operation-key")); }
    }
    void ownerAndHolderCookiesAndCredentialsStaySeparate() {
        TlsServer server; setup(server);
        server.response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: __Host-pki_session=opaque; Path=/; Secure; HttpOnly; SameSite=Strict\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
        SigningHttpClient owner(true), holder(false); QVERIFY(owner.configure(url(server), {}, clientTls())); QVERIFY(holder.configure(url(server), {}, clientTls()));
        for (int i = 0; i < 3; ++i) {
            bool done = false; auto &http = i < 2 ? owner : holder;
            http.send(i == 1 ? QByteArray("POST") : QByteArray("GET"), url(server), i == 1 ? QByteArray("{}") : QByteArray{}, token, "csrf-value", {}, 200, [&](auto r) { QVERIFY2(r.ok, qPrintable(r.error)); done = true; });
            QTRY_VERIFY_WITH_TIMEOUT(done, 5000);
        }
        QCOMPARE(server.requests.size(), 3);
        QVERIFY(!server.requests[0].contains("Authorization:"));
        QVERIFY(server.requests[1].contains("Cookie: __Host-pki_session=opaque")); QVERIFY(server.requests[1].contains("X-CSRF-Token: csrf-value"));
        QVERIFY(server.requests[2].contains("Authorization: Bearer ist_")); QVERIFY(!server.requests[2].contains("Cookie:")); QVERIFY(!server.requests[2].contains("X-CSRF-Token:"));
        owner.clear(); QVERIFY(!owner.hasOwnerCookie());
    }
    void retryAfterIsRespectedAndProblemTextIsRedacted() {
        TlsServer server; setup(server);
        server.response = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        SigningHttpClient http(false); QVERIFY(http.configure(url(server), {}, clientTls()));
        bool done = false; SigningHttpResult response;
        http.send("POST", url(server), "{}", token, {}, "operation-key", 201, [&](auto r) { response = r; done = true; });
        QTRY_VERIFY_WITH_TIMEOUT(done, 5000); QVERIFY(response.retryAt > QDateTime::currentDateTimeUtc().addSecs(55)); QCOMPARE(server.requests.size(), 1);
        const QByteArray problem = QJsonDocument(QJsonObject{{QStringLiteral("detail"), QString::fromLatin1(token)}}).toJson();
        QVERIFY(!safeProblem(401, problem, "application/problem+json").contains(QString::fromLatin1(token)));
    }
};
QTEST_GUILESS_MAIN(TestSigning)
#include "TestSigning.moc"

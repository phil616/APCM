#include "domain/enrollment/EnrollmentRequest.h"
#include "domain/signing/SigningProtocol.h"
#include "platform/windows/cert_enroll/WindowsCertEnrollBackend.h"
#include <QtTest>
#include <QDir>
#include <QSaveFile>
#include <QScopeGuard>
#include <Windows.h>
#include <ncrypt.h>

using namespace certmgr;
class TestIndependentEnrollment final : public QObject {
    Q_OBJECT
private slots:
    void nativeCsrConformsToIndependentProtocol_data()
    {
        QTest::addColumn<QString>("algorithm"); QTest::addColumn<int>("bits");
        QTest::newRow("ECDSA-P256") << QStringLiteral("ECDSA_P256") << 256;
        QTest::newRow("ECDSA-P384") << QStringLiteral("ECDSA_P384") << 384;
        QTest::newRow("RSA-2048") << QStringLiteral("RSA") << 2048;
        QTest::newRow("RSA-3072") << QStringLiteral("RSA") << 3072;
        QTest::newRow("RSA-4096") << QStringLiteral("RSA") << 4096;
    }
    void nativeCsrConformsToIndependentProtocol()
    {
        QFETCH(QString, algorithm); QFETCH(int, bits);
        domain::CertificateTemplate request;
        request.id = QStringLiteral("apcm-independent-regression");
        request.csrProfile = domain::CsrProfile::IndependentSigning;
        request.friendlyName = QStringLiteral("APCM independent CSR regression");
        request.key.provider = QStringLiteral("Microsoft Software Key Storage Provider");
        request.key.algorithm = algorithm; request.key.bits = bits;
        request.subject.insert(QStringLiteral("CN"), {domain::FieldSource::Fixed, QStringLiteral("apcm-csr-smoke.example.test"), {}, false});
        request.subject.insert(QStringLiteral("C"), {domain::FieldSource::Fixed, QStringLiteral("CN"), {}, false});
        request.subject.insert(QStringLiteral("O"), {domain::FieldSource::Fixed, QStringLiteral("APCM 互操作测试"), {}, false});
        request.dnsSans = {QStringLiteral("apcm-csr-smoke.example.test")};
        request.ipSans = {QStringLiteral("10.20.0.9")};
        request.emailSans = {QStringLiteral("smoke@example.test")};
        request.uriSans = {QStringLiteral("spiffe://example.test/workloads/smoke")};
        platform::windows::WindowsCertEnrollBackend backend;
        const auto generated = backend.createPkcs10(request);
        QVERIFY2(generated, generated ? "" : qPrintable(generated.error().message));
        const auto cleanup = qScopeGuard([&] {
            NCRYPT_PROV_HANDLE provider = 0; NCRYPT_KEY_HANDLE key = 0;
            if (NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0) == ERROR_SUCCESS) {
                if (NCryptOpenKey(provider, &key, reinterpret_cast<LPCWSTR>(generated->keyContainerName.utf16()), 0, 0) == ERROR_SUCCESS)
                    if (NCryptDeleteKey(key, 0) != ERROR_SUCCESS) NCryptFreeObject(key);
                NCryptFreeObject(provider);
            }
        });
        const QByteArray pem = generated->csrBase64.toUtf8();
        QVERIFY(pem.startsWith("-----BEGIN CERTIFICATE REQUEST-----\n"));
        QVERIFY(!pem.contains("NEW CERTIFICATE REQUEST"));
        auto inspected = domain::signing::inspectCsr(pem);
        QVERIFY2(inspected, inspected ? "" : qPrintable(inspected.error().message));
        QCOMPARE(inspected->value(QStringLiteral("sans")).toStringList().size(), 4);
        auto wire = domain::signing::issueRequestBody(pem, 3600); QVERIFY(wire);
        const QString fixtures = qEnvironmentVariable("APCM_CSR_FIXTURE_DIR");
        if (!fixtures.isEmpty()) {
            QVERIFY(QDir().mkpath(fixtures));
            const QString name = QString::fromLatin1(QTest::currentDataTag());
            for (const auto &output : {qMakePair(QStringLiteral(".csr"), pem), qMakePair(QStringLiteral(".request.json"), *wire)}) {
                QSaveFile file(QDir(fixtures).filePath(name + output.first));
                QVERIFY(file.open(QIODevice::WriteOnly)); QCOMPARE(file.write(output.second), output.second.size()); QVERIFY(file.commit());
            }
        }
    }
    void independentProfileRejectsRequestedKuOrEkuBeforeCreatingKeys()
    {
        domain::CertificateTemplate request;
        request.csrProfile = domain::CsrProfile::IndependentSigning;
        request.keyUsage = {QStringLiteral("digitalSignature")};
        platform::windows::WindowsCertEnrollBackend backend;
        const auto result = backend.createPkcs10(request);
        QVERIFY(!result); QCOMPARE(result.error().code, QStringLiteral("enrollment.independent_profile"));
    }
};
QTEST_GUILESS_MAIN(TestIndependentEnrollment)
#include "TestIndependentEnrollment.moc"

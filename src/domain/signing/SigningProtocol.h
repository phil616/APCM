#pragma once

#include "../AppError.h"
#include <QJsonObject>
#include <QSslConfiguration>
#include <QUrl>
#include <QVariantMap>
#include <tl/expected.hpp>

namespace certmgr::domain::signing {
template<class T> using Result = tl::expected<T, AppError>;

Result<QUrl> issueEndpoint(const QString &text);
Result<QUrl> consoleEndpoint(const QString &text);
bool isUuid(const QString &text);
bool validToken(const QByteArray &token);
bool validReason(int reason);
Result<QByteArray> readFile(const QUrl &url, qsizetype limit);
Result<QByteArray> canonicalCsrPem(const QByteArray &pem);
Result<QVariantMap> inspectCsr(const QByteArray &pem);
Result<QByteArray> issueRequestBody(const QByteArray &csr, int validitySeconds);
Result<QVariantMap> inspectCertificate(const QJsonObject &record, const QByteArray &csr,
                                      const QStringList &expectedEkus, const QByteArray &trustedRoots);
Result<QVariantMap> inspectIssuer(const QByteArray &der);
Result<QVariantMap> inspectCrl(const QByteArray &der, const QByteArray &issuerDer, const QUrl &issueUrl);
Result<void> validatePolicy(const QJsonObject &policy);
Result<void> validateCaImport(const QByteArray &certificate, const QByteArray &key, const QByteArray &chain);
Result<QSslConfiguration> transportConfiguration(const QVariantMap &settings, QByteArray password,
                                                 bool loadIdentity);
QString transportIdentitySummary(const QSslConfiguration &configuration);
QString fingerprint(const QByteArray &bytes);
QString safeProblem(int status, const QByteArray &body, const QByteArray &contentType);
} // namespace certmgr::domain::signing

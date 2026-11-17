#pragma once

#include "../domain/signing/SigningProtocol.h"
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QPointer>
#include <QSslKey>
#include <functional>

namespace certmgr::services {
struct SigningHttpResult {
    int status{0};
    QByteArray body;
    QByteArray contentType;
    QString requestId;
    QString problemCode;
    QString error;
    QDateTime retryAt;
    bool replayed{false};
    bool ok{false};
};

// One isolated network session per role. No redirects or TLS verification bypasses.
class SigningHttpClient final : public QObject {
    Q_OBJECT
public:
    explicit SigningHttpClient(bool owner, QObject *parent = nullptr);
    domain::signing::Result<void> configure(const QUrl &base, const QVariantMap &settings,
                                           const QSslConfiguration &tls);
    void send(const QByteArray &method, const QUrl &url, QByteArray body, QByteArray token,
              const QByteArray &csrf, const QByteArray &idempotencyKey, int expectedStatus,
              std::function<void(SigningHttpResult)> completed);
    void clear();
    bool hasOwnerCookie() const;
    const QSslConfiguration &tls() const { return tls_; }
    bool hasIdentity() const { return !tls_.localCertificate().isNull() && !tls_.privateKey().isNull(); }
private:
    QNetworkAccessManager manager_;
    QPointer<QNetworkReply> active_;
    QUrl base_;
    QVariantMap settings_;
    QSslConfiguration tls_;
    bool owner_{false};
};
} // namespace certmgr::services

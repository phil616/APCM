#include "AppController.h"
#include "SingleInstanceGuard.h"

#include <QCryptographicHash>
#include <QDir>
#include <QGuiApplication>
#include <QFont>
#include <QIcon>
#include <QStandardPaths>
#include <QWindow>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("DreamReflexOpenSource"));
    // Keep the internal name stable so existing encrypted vault paths remain valid.
    QCoreApplication::setApplicationName(QStringLiteral("Certificate Manager"));
    QGuiApplication::setApplicationDisplayName(QStringLiteral("证书管理器"));
    QCoreApplication::setApplicationVersion(QStringLiteral(CERTMGR_VERSION));

    const QString appDataDirectory =
        QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (!QDir().mkpath(appDataDirectory)) {
        qCritical("Unable to create the APCM application data directory.");
        return 2;
    }
    const QByteArray instanceHash = QCryptographicHash::hash(
        QDir::toNativeSeparators(appDataDirectory).toCaseFolded().toUtf8(),
        QCryptographicHash::Sha256).toHex().left(24);
    certmgr::app::SingleInstanceGuard instanceGuard(
        QDir(appDataDirectory).filePath(QStringLiteral("apcm.instance.lock")),
        QStringLiteral("AltasCI.APCM.%1").arg(QString::fromLatin1(instanceHash)));
    QString instanceMessage;
    const auto instanceRole = instanceGuard.start(&instanceMessage);
    if (instanceRole == certmgr::app::SingleInstanceGuard::Role::Secondary) {
        if (!instanceMessage.isEmpty()) qWarning("%s", qPrintable(instanceMessage));
        return 0;
    }
    if (instanceRole == certmgr::app::SingleInstanceGuard::Role::Error) {
        qCritical("%s", qPrintable(instanceMessage));
        return 2;
    }

    QQuickStyle::setStyle(QStringLiteral("Basic"));
    QFont::insertSubstitutions(QStringLiteral("CertManager UI"),
                               {QStringLiteral("Consolas"), QStringLiteral("SimHei")});
    QFont applicationFont;
    applicationFont.setFamilies({QStringLiteral("Consolas"), QStringLiteral("SimHei")});
    app.setFont(applicationFont);
    app.setWindowIcon(QIcon(QStringLiteral(":/icon.png")));

    certmgr::app::AppController controller;
    QQmlApplicationEngine engine;
    QObject::connect(&instanceGuard, &certmgr::app::SingleInstanceGuard::activationRequested,
                     &app, [&engine] {
        for (QObject *root : engine.rootObjects()) {
            auto *window = qobject_cast<QWindow *>(root);
            if (!window) continue;
            if (window->windowStates().testFlag(Qt::WindowMinimized)) window->showNormal();
            else window->show();
            window->raise();
            window->requestActivate();
#ifdef Q_OS_WIN
            const auto nativeWindow = reinterpret_cast<HWND>(window->winId());
            if (IsIconic(nativeWindow)) ShowWindow(nativeWindow, SW_RESTORE);
            BringWindowToTop(nativeWindow);
            SetForegroundWindow(nativeWindow);
#endif
            break;
        }
    });
    engine.rootContext()->setContextProperty(QStringLiteral("App"), &controller);
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed, &app,
                     [] { QCoreApplication::exit(-1); }, Qt::QueuedConnection);
    engine.loadFromModule(QStringLiteral("CertManager"), QStringLiteral("Main"));
    return app.exec();
}

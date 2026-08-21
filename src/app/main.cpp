#include "AppController.h"

#include <QGuiApplication>
#include <QFont>
#include <QIcon>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("DreamReflexOpenSource"));
    // Keep the internal name stable so existing encrypted vault paths remain valid.
    QCoreApplication::setApplicationName(QStringLiteral("Certificate Manager"));
    QGuiApplication::setApplicationDisplayName(QStringLiteral("证书管理器"));
    QCoreApplication::setApplicationVersion(QStringLiteral("0.1.0"));
    QQuickStyle::setStyle(QStringLiteral("Basic"));
    QFont::insertSubstitutions(QStringLiteral("CertManager UI"),
                               {QStringLiteral("Consolas"), QStringLiteral("SimHei")});
    QFont applicationFont;
    applicationFont.setFamilies({QStringLiteral("Consolas"), QStringLiteral("SimHei")});
    app.setFont(applicationFont);
    app.setWindowIcon(QIcon(QStringLiteral(":/icon.png")));

    certmgr::app::AppController controller;
    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty(QStringLiteral("App"), &controller);
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed, &app,
                     [] { QCoreApplication::exit(-1); }, Qt::QueuedConnection);
    engine.loadFromModule(QStringLiteral("CertManager"), QStringLiteral("Main"));
    return app.exec();
}

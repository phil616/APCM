#pragma once

#include <QLocalServer>
#include <QLockFile>
#include <QObject>
#include <QString>

namespace certmgr::app {

class SingleInstanceGuard final : public QObject {
    Q_OBJECT

public:
    enum class Role {
        Primary,
        Secondary,
        Error,
    };
    Q_ENUM(Role)

    explicit SingleInstanceGuard(QString lockFilePath, QString serverName,
                                 QObject *parent = nullptr);
    ~SingleInstanceGuard() override;

    Role start(QString *message = nullptr);

signals:
    void activationRequested();

private:
    bool notifyPrimary(QString *message);
    void acceptConnections();

    QLockFile lock_;
    QLocalServer server_;
    QString serverName_;
    bool started_{false};
#ifdef Q_OS_WIN
    void *mutexHandle_{nullptr};
#endif
};

} // namespace certmgr::app

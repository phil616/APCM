#include "SingleInstanceGuard.h"

#include <QElapsedTimer>
#include <QLocalSocket>
#include <QThread>

#include <limits>
#include <utility>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace certmgr::app {

SingleInstanceGuard::SingleInstanceGuard(QString lockFilePath, QString serverName,
                                         QObject *parent)
    : QObject(parent), lock_(std::move(lockFilePath)), serverName_(std::move(serverName))
{
    // A GUI instance owns the lock for its entire lifetime. Time alone must never make it stale.
    lock_.setStaleLockTime(0);
}

SingleInstanceGuard::~SingleInstanceGuard()
{
    server_.close();
    lock_.unlock();
#ifdef Q_OS_WIN
    if (mutexHandle_) CloseHandle(static_cast<HANDLE>(mutexHandle_));
#endif
}

SingleInstanceGuard::Role SingleInstanceGuard::start(QString *message)
{
    if (started_) {
        if (message) *message = QStringLiteral("单实例守卫不能重复启动。");
        return Role::Error;
    }
    started_ = true;

    bool isPrimary = false;
#ifdef Q_OS_WIN
    const QString mutexName = QStringLiteral("Local\\%1").arg(serverName_);
    const HANDLE mutex = CreateMutexW(nullptr, FALSE,
        reinterpret_cast<LPCWSTR>(mutexName.utf16()));
    if (!mutex) {
        if (message) *message = QStringLiteral("无法创建 Windows 单实例互斥锁。");
        return Role::Error;
    }
    const DWORD mutexStatus = GetLastError();
    mutexHandle_ = mutex;
    isPrimary = mutexStatus != ERROR_ALREADY_EXISTS;
    if (isPrimary && !lock_.tryLock(0)) {
        // The kernel mutex proves there is no live new-version owner. Recover an orphaned file lock.
        if (lock_.error() != QLockFile::LockFailedError
            || !lock_.removeStaleLockFile() || !lock_.tryLock(0)) {
            if (message) *message = QStringLiteral("无法创建单实例进程锁。");
            return Role::Error;
        }
    }
#else
    isPrimary = lock_.tryLock(0);
#endif

    if (isPrimary) {
        // Holding the process lock proves that no live APCM instance owns this endpoint.
        QLocalServer::removeServer(serverName_);
        server_.setSocketOptions(QLocalServer::UserAccessOption);
        if (!server_.listen(serverName_)) {
            if (message) {
                *message = QStringLiteral("无法创建单实例通信端点：%1").arg(server_.errorString());
            }
            lock_.unlock();
            return Role::Error;
        }
        connect(&server_, &QLocalServer::newConnection,
                this, &SingleInstanceGuard::acceptConnections);
        return Role::Primary;
    }

#ifndef Q_OS_WIN
    if (lock_.error() != QLockFile::LockFailedError) {
        if (message) *message = QStringLiteral("无法创建单实例进程锁。");
        return Role::Error;
    }
#endif

    // Never open a second vault writer. Activation is best-effort, uniqueness is mandatory.
    static_cast<void>(notifyPrimary(message));
    return Role::Secondary;
}

bool SingleInstanceGuard::notifyPrimary(QString *message)
{
    QElapsedTimer timer;
    timer.start();
    do {
#ifdef Q_OS_WIN
        qint64 primaryPid = 0;
        QString hostName;
        QString applicationName;
        if (lock_.getLockInfo(&primaryPid, &hostName, &applicationName)
            && primaryPid > 0 && primaryPid <= std::numeric_limits<DWORD>::max()) {
            // The user-launched process grants the primary permission to take foreground focus.
            AllowSetForegroundWindow(static_cast<DWORD>(primaryPid));
        }
#endif
        QLocalSocket socket;
        socket.connectToServer(serverName_, QIODevice::WriteOnly);
        if (socket.waitForConnected(150)) {
            socket.write("activate\n");
            socket.waitForBytesWritten(250);
            socket.disconnectFromServer();
            return true;
        }
        socket.abort();
        QThread::msleep(25);
    } while (timer.elapsed() < 1500);

    if (message) {
        *message = QStringLiteral("APCM 已在运行，但现有窗口暂时无法响应激活请求。");
    }
    return false;
}

void SingleInstanceGuard::acceptConnections()
{
    while (server_.hasPendingConnections()) {
        auto *socket = server_.nextPendingConnection();
        if (!socket) continue;
        connect(socket, &QLocalSocket::disconnected, socket, &QObject::deleteLater);
        emit activationRequested();
        socket->disconnectFromServer();
        if (socket->state() == QLocalSocket::UnconnectedState) socket->deleteLater();
    }
}

} // namespace certmgr::app

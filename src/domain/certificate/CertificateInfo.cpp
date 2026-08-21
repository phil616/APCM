#include "CertificateInfo.h"

namespace certmgr::domain {

QString storeScopeName(const StoreScope scope)
{
    switch (scope) {
    case StoreScope::User: return QStringLiteral("当前用户");
    case StoreScope::Machine: return QStringLiteral("本地计算机");
    case StoreScope::Service: return QStringLiteral("服务");
    }
    return QStringLiteral("未知");
}

QString storeRoleName(const StoreRole role)
{
    switch (role) {
    case StoreRole::Personal: return QStringLiteral("个人");
    case StoreRole::TrustedRoot: return QStringLiteral("受信任的根 CA");
    case StoreRole::IntermediateCA: return QStringLiteral("中间 CA");
    case StoreRole::EnterpriseTrust: return QStringLiteral("企业信任");
    case StoreRole::EnrollmentRequest: return QStringLiteral("证书申请");
    case StoreRole::Other: return QStringLiteral("其他");
    }
    return QStringLiteral("未知");
}

} // namespace certmgr::domain

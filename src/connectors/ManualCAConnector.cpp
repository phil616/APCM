#include "ManualCAConnector.h"

namespace certmgr::connectors {
namespace {

domain::AppError manualAction(QString code, QString message)
{
    return {domain::ErrorCategory::Enrollment, std::move(code), 0, std::move(message),
            QStringLiteral("手动连接器不会联系或模拟任何证书颁发机构。")};
}

} // namespace

tl::expected<platform::SubmitResult, domain::AppError>
ManualCAConnector::submit(const platform::CertificateRequestPayload &request)
{
    return platform::SubmitResult{request.localRequestId,
        QStringLiteral("请导出 CSR，并通过获准的外部流程提交给 CA。")};
}

tl::expected<platform::RequestStatus, domain::AppError>
ManualCAConnector::query(const QString &)
{
    return platform::RequestStatus{platform::RemoteRequestState::ManualActionRequired,
        QStringLiteral("CA 完成申请后，请导入已签发的证书。")};
}

tl::expected<platform::CertificateResponse, domain::AppError>
ManualCAConnector::retrieve(const QString &)
{
    return tl::unexpected(manualAction(QStringLiteral("manual.retrieve"),
        QStringLiteral("手动连接器无法自动获取证书。")));
}

tl::expected<void, domain::AppError>
ManualCAConnector::revoke(const QString &, const QString &)
{
    return tl::unexpected(manualAction(QStringLiteral("manual.revoke"),
        QStringLiteral("请通过 CA 认可的外部流程提交吊销申请。")));
}

} // namespace certmgr::connectors

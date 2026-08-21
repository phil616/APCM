#pragma once

#include "../domain/AppError.h"
#include "../domain/templates/CertificateTemplate.h"

#include <tl/expected.hpp>
#include <vector>

namespace certmgr::services {

class TemplateService {
public:
    [[nodiscard]] std::vector<domain::CertificateTemplate> builtInTemplates() const;
    [[nodiscard]] tl::expected<domain::CertificateTemplate, domain::AppError>
        resolveAndValidate(const domain::CertificateTemplate &source) const;

private:
    static QString resolveField(const domain::TemplateField &field);
};

} // namespace certmgr::services


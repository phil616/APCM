#pragma once

#include <QString>

namespace certmgr::domain {

struct PrivateKeyInfo {
    QString provider;
    QString container;
    QString algorithm;
    int bits{0};
    bool machineKey{false};
    bool exportable{false};
    bool hardwareBacked{false};
    bool tpmBacked{false};
    QString linkedCertificateFingerprint;
};

} // namespace certmgr::domain


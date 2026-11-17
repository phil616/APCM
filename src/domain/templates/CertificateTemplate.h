#pragma once

#include "../certificate/CertificateInfo.h"

#include <QJsonObject>
#include <QRegularExpression>
#include <QStringList>

namespace certmgr::domain {

enum class CsrProfile { Standard, IndependentSigning };

enum class FieldSource { Fixed, UserInput, ComputerName, Username, Environment, Generated, ServerAssigned };

struct TemplateField {
    FieldSource source{FieldSource::UserInput};
    QString value;
    QRegularExpression pattern;
    bool editable{true};
};

struct KeyPolicy {
    QString provider{QStringLiteral("software")};
    QString algorithm{QStringLiteral("RSA")};
    int bits{2048};
    bool exportable{false};
    bool hardwareRequired{false};
    bool attestationRequired{false};
};

struct CertificateTemplate {
    QString id;
    QString name;
    int version{1};
    bool enabled{true};
    StoreScope scope{StoreScope::User};
    CsrProfile csrProfile{CsrProfile::Standard};
    QHash<QString, TemplateField> subject;
    QStringList dnsSans;
    QStringList ipSans;
    QStringList uriSans;
    QStringList upnSans;
    QStringList emailSans;
    KeyPolicy key;
    QStringList keyUsage;
    QStringList extendedKeyUsage;
    QString friendlyName;
};

} // namespace certmgr::domain


import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CertManager

ColumnLayout {
    id: root
    spacing: 8
    function lines(value) { return value.split(/[,;\s]+/).filter(function(s) { return s.length > 0 }) }
    function load(policy) {
        dns.text = (policy.allowed_dns_names || []).join("\n")
        ip.text = (policy.allowed_ip_ranges || []).join("\n")
        email.text = (policy.allowed_email_domains || []).join("\n")
        uri.text = (policy.allowed_uri_prefixes || []).join("\n")
        wildcard.checked = policy.allow_wildcards || false
        server.checked = (policy.extended_key_usages || ["server_auth"]).indexOf("server_auth") >= 0
        client.checked = (policy.extended_key_usages || []).indexOf("client_auth") >= 0
        defaultValidity.value = policy.default_validity_seconds || 86400
        maxValidity.value = policy.max_validity_seconds || 604800
        maxSans.value = policy.max_sans || 32
    }
    function value() {
        var ekus = []
        if (server.checked) ekus.push("server_auth")
        if (client.checked) ekus.push("client_auth")
        return {version: 1, allowed_dns_names: lines(dns.text), allowed_ip_ranges: lines(ip.text),
            allowed_email_domains: lines(email.text), allowed_uri_prefixes: lines(uri.text),
            allow_wildcards: wildcard.checked, extended_key_usages: ekus,
            default_validity_seconds: defaultValidity.value, max_validity_seconds: maxValidity.value,
            max_sans: maxSans.value}
    }
    Label { Layout.fillWidth: true; text: "完整策略 · 每类最多 100 项；空白名单表示拒绝该类身份。实例与 Token 策略取交集。"; wrapMode: Text.WordWrap; color: Theme.textMuted; font.pixelSize: 11 }
    GridLayout {
        Layout.fillWidth: true; columns: 2; columnSpacing: 12; rowSpacing: 6
        Label { text: "DNS 白名单（精确域名或 *.example.com）"; color: Theme.text; font.pixelSize: 11 }
        Label { text: "IP 范围（IPv4 / IPv6 CIDR）"; color: Theme.text; font.pixelSize: 11 }
        ScrollView { Layout.fillWidth: true; Layout.preferredHeight: 78; clip: true; TextArea { id: dns; placeholderText: "db.example.com\n*.services.example.com"; wrapMode: TextEdit.Wrap; font.pixelSize: 11 } }
        ScrollView { Layout.fillWidth: true; Layout.preferredHeight: 78; clip: true; TextArea { id: ip; placeholderText: "10.20.0.0/16"; wrapMode: TextEdit.Wrap; font.pixelSize: 11 } }
        Label { text: "邮箱域名白名单"; color: Theme.text; font.pixelSize: 11 }
        Label { text: "HTTPS / SPIFFE URI 前缀"; color: Theme.text; font.pixelSize: 11 }
        ScrollView { Layout.fillWidth: true; Layout.preferredHeight: 66; clip: true; TextArea { id: email; placeholderText: "example.com"; wrapMode: TextEdit.Wrap; font.pixelSize: 11 } }
        ScrollView { Layout.fillWidth: true; Layout.preferredHeight: 66; clip: true; TextArea { id: uri; placeholderText: "spiffe://example.com/workloads/"; wrapMode: TextEdit.Wrap; font.pixelSize: 11 } }
    }
    RowLayout {
        CheckBox { id: wildcard; text: "允许实际通配符证书"; font.pixelSize: 11 }
        CheckBox { id: server; text: "server_auth"; checked: true; font.pixelSize: 11 }
        CheckBox { id: client; text: "client_auth"; font.pixelSize: 11 }
    }
    GridLayout {
        columns: 4; columnSpacing: 8
        Label { text: "默认有效期 / 秒"; font.pixelSize: 11 }
        SpinBox { id: defaultValidity; from: 60; to: 34300800; value: 86400; editable: true }
        Label { text: "最大有效期 / 秒"; font.pixelSize: 11 }
        SpinBox { id: maxValidity; from: 60; to: 34300800; value: 604800; editable: true }
        Label { text: "SAN 数量上限"; font.pixelSize: 11 }
        SpinBox { id: maxSans; from: 1; to: 100; value: 32; editable: true }
    }
}

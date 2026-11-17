import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import CertManager

// qmllint disable unqualified

ColumnLayout {
    id: root
    spacing: 8
    property alias password: identityPassword.text
    function load(settings) {
        requiredIdentity.checked = settings.mtlsRequired || false
        certificateFile.text = settings.clientCertificateFile || ""
        keyFile.text = settings.clientKeyFile || ""
        serverCa.text = settings.serverCaFile || ""
        identityPassword.clear()
        timeout.value = settings.timeoutSeconds || 30
        proxyType.currentIndex = Math.max(0, ["system", "direct", "http", "socks5"].indexOf(settings.proxyType || "system"))
        proxyHost.text = settings.proxyHost || ""
        proxyPort.value = settings.proxyPort || 8080
    }
    function configuration() {
        return { mtlsRequired: requiredIdentity.checked,
            clientCertificateFile: certificateFile.text, clientKeyFile: keyFile.text,
            serverCaFile: serverCa.text, timeoutSeconds: timeout.value,
            proxyType: ["system", "direct", "http", "socks5"][proxyType.currentIndex],
            proxyHost: proxyHost.text, proxyPort: proxyPort.value }
    }
    function pick(input, filters) {
        filePicker.targetInput = input
        filePicker.nameFilters = filters
        filePicker.open()
    }
    Label { text: "HTTP 通信安全"; font.bold: true; font.pixelSize: 13; color: Theme.text }
    Label {
        Layout.fillWidth: true
        text: "通信客户端证书仅用于向 nginx 等入口证明身份。它与签发 Token、业务叶证书及签发 CA 相互独立。"
        wrapMode: Text.WordWrap; color: Theme.textMuted; font.pixelSize: 11
    }
    CheckBox { id: requiredIdentity; text: "此端点要求 mTLS（未加载通信身份时阻止请求）"; font.pixelSize: 11 }
    GridLayout {
        Layout.fillWidth: true; columns: 3; columnSpacing: 8; rowSpacing: 8
        Label { text: "通信证书"; color: Theme.text; font.pixelSize: 11 }
        TextField { id: certificateFile; Layout.fillWidth: true; readOnly: true; placeholderText: "P12/PFX，或含客户端证书链的 PEM"; font.pixelSize: 11 }
        Button { text: "选择…"; onClicked: root.pick(certificateFile, ["客户端证书 (*.p12 *.pfx *.pem *.crt)", "所有文件 (*)"]) }
        Label { text: "通信私钥"; color: Theme.text; font.pixelSize: 11 }
        TextField { id: keyFile; Layout.fillWidth: true; readOnly: true; placeholderText: "PFX 请留空；PEM 证书请选择配对私钥"; font.pixelSize: 11 }
        RowLayout {
            Button { text: "选择…"; onClicked: root.pick(keyFile, ["PEM 私钥 (*.key *.pem)", "所有文件 (*)"]) }
            Button { text: "清空"; onClicked: keyFile.clear() }
        }
        Label { text: "私钥密码"; color: Theme.text; font.pixelSize: 11 }
        TextField { id: identityPassword; Layout.fillWidth: true; echoMode: TextInput.Password; placeholderText: "只用于本次加载，不保存"; font.pixelSize: 11 }
        Button { text: "清除身份"; onClicked: { certificateFile.clear(); keyFile.clear(); identityPassword.clear() } }
        Label { text: "服务器信任根"; color: Theme.text; font.pixelSize: 11 }
        TextField { id: serverCa; Layout.fillWidth: true; readOnly: true; placeholderText: "可选：HTTPS 服务器私有 CA；默认使用系统信任"; font.pixelSize: 11 }
        RowLayout {
            Button { text: "选择…"; onClicked: root.pick(serverCa, ["CA 证书 (*.pem *.cer *.crt *.der)", "所有文件 (*)"]) }
            Button { text: "清空"; onClicked: serverCa.clear() }
        }
        Label { text: "请求超时"; color: Theme.text; font.pixelSize: 11 }
        RowLayout { SpinBox { id: timeout; from: 5; to: 120; value: 30; editable: true } Label { text: "秒"; color: Theme.textMuted } }
        Item { }
        Label { text: "网络代理"; color: Theme.text; font.pixelSize: 11 }
        ComboBox { id: proxyType; Layout.fillWidth: true; model: ["系统代理", "直接连接", "HTTP 代理", "SOCKS5 代理"]; font.pixelSize: 11 }
        Item { }
        Label { visible: proxyType.currentIndex > 1; text: "代理主机 / 端口"; color: Theme.text; font.pixelSize: 11 }
        TextField { id: proxyHost; visible: proxyType.currentIndex > 1; Layout.fillWidth: true; placeholderText: "代理主机"; font.pixelSize: 11 }
        SpinBox { id: proxyPort; visible: proxyType.currentIndex > 1; from: 1; to: 65535; value: 8080; editable: true }
    }
    Label {
        Layout.fillWidth: true
        text: "PFX/PEM 私钥仅在当前解锁会话中使用。重新解锁或切换连接后，请再次加载通信身份。所有请求始终校验 HTTPS 证书和主机名，并禁止自动跳转。"
        color: Theme.textDim; wrapMode: Text.WordWrap; font.pixelSize: 10
    }
    Connections {
        target: App
        function onVaultStateChanged() { if (!App.unlocked) { identityPassword.clear(); filePicker.close() } }
    }
    FileDialog {
        id: filePicker
        property var targetInput
        title: "选择通信证书或信任根"
        onAccepted: if (targetInput) targetInput.text = selectedFile.toString()
    }
}

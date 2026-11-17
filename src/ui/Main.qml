import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import CertManager
import "components"

// qmllint disable unqualified

ApplicationWindow {
    id: window
    width: 1280
    height: 800
    minimumWidth: 1040
    minimumHeight: 680
    visible: true
    color: Theme.ink
    title: "APCM - AltasCI multi-Platform Certificate Manager"
    onClosing: App.prepareForExit()

    property int pageIndex: 0
    property string selectedCertificateId: ""
    property var selectedDetails: ({})
    property string selectedRequestId: ""
    property string generatedCsr: ""
    property url selectedInstallFile
    property var packagePreview: ({})
    property bool packageIsPkcs12: false
    property int installDefaultRole: 0

    function chooseCertificatePackage(defaultRole) {
        installDefaultRole = defaultRole
        certificatePackageFileDialog.open()
    }

    function openRequestEditor(templateId, templateName) {
        requestEditor.templateId = templateId
        requestEditor.templateName = templateName
        requestName.text = templateName
        requestCn.text = ""
        requestOrg.text = "AltasCI"
        requestOu.text = ""
        requestLocality.text = ""
        requestState.text = ""
        requestCountry.text = ""
        requestDns.text = ""
        requestIp.text = ""
        requestUri.text = ""
        requestUpn.text = ""
        requestScope.currentIndex = templateId === "windows-device-mtls" ? 1 : 0
        requestProvider.currentIndex = templateId === "windows-device-mtls" ? 1 : 0
        requestBits.currentIndex = 0
        requestExportable.checked = false
        requestDigitalSignature.checked = true
        requestKeyEncipherment.checked = false
        requestDataEncipherment.checked = false
        requestKeyAgreement.checked = false
        requestNonRepudiation.checked = false
        requestClientAuth.checked = true
        requestServerAuth.checked = false
        requestCodeSigning.checked = false
        requestEmailProtection.checked = false
        requestCustomEku.text = ""
        requestValidity.value = 365
        requestEditor.open()
    }

    component CommandButton: Button {
        id: control
        property bool primary: false
        implicitHeight: 28
        leftPadding: 12
        rightPadding: 12
        contentItem: Text {
            text: control.text
            color: control.enabled ? (control.primary ? "white" : Theme.text) : "#888888"
            font.family: Theme.uiFont
            font.pixelSize: 11
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
        }
        background: Rectangle {
            color: !control.enabled ? "#E1E1E1" : control.primary
                ? (control.hovered ? "#005A9E" : Theme.mint)
                : (control.hovered ? "#E5E5E5" : "#F7F7F7")
            border.width: 1
            border.color: control.primary ? "#005A9E" : Theme.lineBright
            radius: 1
        }
    }

    component EditBox: TextField {
        id: field
        implicitHeight: 30
        leftPadding: 7
        rightPadding: 7
        color: Theme.text
        placeholderTextColor: Theme.textDim
        selectByMouse: true
        font.family: Theme.uiFont
        font.pixelSize: 11
        background: Rectangle {
            color: Theme.panel
            border.width: 1
            border.color: field.activeFocus ? Theme.mint : Theme.lineBright
            radius: 1
        }
    }

    component TableTitle: Rectangle {
        color: "#F0F0F0"
        border.width: 1
        border.color: Theme.line
        implicitHeight: 30
    }

    UnlockPage { anchors.fill: parent; visible: !App.unlocked }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0
        visible: App.unlocked

        // Traditional application command bar.
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 42
            color: "#FAFAFA"
            border.width: 1
            border.color: Theme.line
            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 10
                anchors.rightMargin: 10
                spacing: 7
                Image {
                    Layout.preferredWidth: 26
                    Layout.preferredHeight: 26
                    source: "qrc:/icon.png"
                    fillMode: Image.PreserveAspectFit
                    smooth: true
                    mipmap: true
                }
                Text { text: "APCM"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 14; font.bold: true }
                Rectangle { Layout.preferredWidth: 1; Layout.preferredHeight: 22; color: Theme.line }
                CommandButton { text: App.busy ? "正在刷新…" : "刷新"; enabled: !App.busy; onClicked: App.refresh() }
                CommandButton { text: "安装证书…"; onClicked: window.chooseCertificatePackage(0) }
                CommandButton { text: "新建申请"; primary: true; onClicked: window.openRequestEditor("windows-user-client-auth", "自定义用户证书") }
                Item { Layout.fillWidth: true }
                Text { text: "已索引 " + App.certificates.count + " 张证书"; color: Theme.textMuted; font.family: Theme.uiFont; font.pixelSize: 10 }
                CommandButton { text: "锁定"; onClicked: App.lockVault() }
                CommandButton { text: "安全退出"; onClicked: App.exitApplication() }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            Rectangle {
                Layout.fillHeight: true
                Layout.preferredWidth: 196
                color: "#F5F5F5"
                border.width: 1
                border.color: Theme.line
                ColumnLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 8
                    anchors.rightMargin: 8
                    anchors.topMargin: 10
                    anchors.bottomMargin: 10
                    spacing: 2
                    Text { Layout.leftMargin: 8; Layout.bottomMargin: 5; text: "管理控制台"; color: Theme.textDim; font.family: Theme.uiFont; font.pixelSize: 10 }
                    Repeater {
                        model: [
                            {label: "总览", mark: "⌂"}, {label: "证书", mark: "▣"},
                            {label: "证书申请", mark: "↗"}, {label: "申请模板", mark: "▤"},
                            {label: "APCM 根证书", mark: "◆"}, {label: "加密密钥", mark: "⚿"},
                            {label: "审计日志", mark: "≡"},
                            {label: "AltasCI 证书管理", mark: "◈"}
                        ]
                        NavButton {
                            Layout.fillWidth: true
                            label: modelData.label
                            mark: modelData.mark
                            current: index === window.pageIndex
                            onClicked: window.pageIndex = index
                        }
                    }
                    Item { Layout.fillHeight: true }
                    Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: Theme.line }
                    Text { Layout.leftMargin: 8; Layout.topMargin: 7; text: App.tpmReady ? "TPM：可用" : "TPM：不可用"; color: App.tpmReady ? Theme.mint : Theme.amber; font.family: Theme.uiFont; font.pixelSize: 10 }
                    Text { Layout.leftMargin: 8; text: "Windows 原生后端"; color: Theme.textDim; font.family: Theme.uiFont; font.pixelSize: 9 }
                }
            }

            StackLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                currentIndex: window.pageIndex

                // Overview
                Item {
                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 10
                        SectionHeading { title: "APCM 总览"; subtitle: "Windows 证书、申请、密钥与托管根证书的当前状态"; Layout.fillWidth: true }
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 132
                            color: Theme.panel
                            border.width: 1
                            border.color: Theme.line
                            ColumnLayout {
                                anchors.fill: parent
                                spacing: 0
                                Rectangle {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 31
                                    color: "#F0F0F0"
                                    Text { anchors.left: parent.left; anchors.leftMargin: 10; anchors.verticalCenter: parent.verticalCenter; text: "资源摘要"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                }
                                RowLayout {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    spacing: 0
                                    Repeater {
                                        model: [
                                            {name: "证书", value: App.certificates.count, note: "Windows 存储"},
                                            {name: "证书申请", value: App.enrollmentRequests.length, note: "保险库记录"},
                                            {name: "加密密钥", value: App.privateKeys.length, note: "CNG 持久密钥"},
                                            {name: "APCM 管理", value: App.managedCertificates.length, note: "自动管理证书"}
                                        ]
                                        Item {
                                            required property var modelData
                                            required property int index
                                            Layout.fillWidth: true
                                            Layout.fillHeight: true
                                            ColumnLayout {
                                                anchors.fill: parent
                                                anchors.leftMargin: 14
                                                anchors.rightMargin: 10
                                                anchors.topMargin: 12
                                                anchors.bottomMargin: 10
                                                spacing: 1
                                                Text { text: modelData.value; color: Theme.mint; font.family: Theme.uiFont; font.pixelSize: 22; font.bold: true }
                                                Text { text: modelData.name; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 11; font.bold: true }
                                                Text { text: modelData.note; color: Theme.textDim; font.family: Theme.uiFont; font.pixelSize: 9 }
                                            }
                                            Rectangle { visible: index < 3; anchors.right: parent.right; anchors.top: parent.top; anchors.bottom: parent.bottom; width: 1; color: Theme.line }
                                        }
                                    }
                                }
                            }
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            spacing: 10
                            Rectangle {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                Layout.horizontalStretchFactor: 3
                                color: Theme.panel
                                border.width: 1
                                border.color: Theme.line
                                ColumnLayout {
                                    anchors.fill: parent
                                    spacing: 0
                                    Rectangle {
                                        Layout.fillWidth: true
                                        Layout.preferredHeight: 31
                                        color: "#F0F0F0"
                                        Text { anchors.left: parent.left; anchors.leftMargin: 10; anchors.verticalCenter: parent.verticalCenter; text: "运行状态"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    }
                                    Repeater {
                                        model: [
                                            {label: "30 天内到期", value: App.expiringSoon + " 张证书", tone: App.expiringSoon > 0 ? Theme.amber : Theme.textMuted},
                                            {label: "TPM 提供程序", value: App.tpmReady ? "可用" : "不可用", tone: App.tpmReady ? Theme.mint : Theme.amber},
                                            {label: "加密保险库", value: App.unlocked ? "已解锁" : "已锁定", tone: App.unlocked ? Theme.mint : Theme.amber}
                                        ]
                                        Item {
                                            required property var modelData
                                            Layout.fillWidth: true
                                            Layout.preferredHeight: 47
                                    RowLayout {
                                        anchors.fill: parent
                                                anchors.leftMargin: 12
                                                anchors.rightMargin: 12
                                                Text { Layout.fillWidth: true; text: modelData.label; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                                                Text { text: modelData.value; color: modelData.tone; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                            }
                                            Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 1; color: Theme.line }
                                        }
                                    }
                                    Item { Layout.fillHeight: true }
                                    RowLayout {
                                        Layout.fillWidth: true
                                        Layout.margins: 8
                                        spacing: 6
                                        CommandButton { text: "查看证书"; onClicked: window.pageIndex = 1 }
                                        CommandButton { text: "查看申请"; onClicked: window.pageIndex = 2 }
                                        Item { Layout.fillWidth: true }
                                        CommandButton { text: "刷新状态"; primary: true; enabled: !App.busy; onClicked: App.refresh() }
                                    }
                                }
                            }
                            Rectangle {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                Layout.horizontalStretchFactor: 2
                                color: Theme.panel
                                border.width: 1
                                border.color: Theme.line
                                ColumnLayout {
                                    anchors.fill: parent
                                    spacing: 0
                                    Rectangle {
                                        Layout.fillWidth: true
                                        Layout.preferredHeight: 31
                                        color: "#F0F0F0"
                                        Text { anchors.left: parent.left; anchors.leftMargin: 10; anchors.verticalCenter: parent.verticalCenter; text: "安全边界"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        Layout.fillHeight: true
                                        Layout.margins: 12
                                        spacing: 9
                                        Text { Layout.fillWidth: true; text: "证书"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                        Text { Layout.fillWidth: true; text: "由 Windows 证书存储托管，是当前安装状态的权威来源。"; color: Theme.textMuted; wrapMode: Text.WordWrap; font.family: Theme.uiFont; font.pixelSize: 10 }
                                        Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: Theme.line }
                                        Text { Layout.fillWidth: true; text: "私钥"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                        Text { Layout.fillWidth: true; text: "始终保留在 CNG、TPM、智能卡或 HSM 中，不写入 APCM 数据库。"; color: Theme.textMuted; wrapMode: Text.WordWrap; font.family: Theme.uiFont; font.pixelSize: 10 }
                                        Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: Theme.line }
                                        Text { Layout.fillWidth: true; text: "管理操作"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                        Text { Layout.fillWidth: true; text: "删除证书不删除私钥；移出 APCM 管理不删除 Windows 根证书。"; color: Theme.mint; wrapMode: Text.WordWrap; font.family: Theme.uiFont; font.pixelSize: 10 }
                                        Item { Layout.fillHeight: true }
                                        CommandButton { Layout.alignment: Qt.AlignRight; text: "查看审计日志"; onClicked: window.pageIndex = 6 }
                                    }
                                }
                            }
                        }
                    }
                }

                // Certificate inventory
                Item {
                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8
                        RowLayout {
                            Layout.fillWidth: true
                            SectionHeading { Layout.fillWidth: true; title: "证书"; subtitle: "当前用户与本地计算机证书存储" }
                            CommandButton { text: "安装证书…"; primary: true; onClicked: window.chooseCertificatePackage(0) }
                            EditBox { id: certificateSearch; Layout.preferredWidth: 270; placeholderText: "搜索主题或颁发者" }
                        }
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            color: Theme.panel
                            border.width: 1
                            border.color: Theme.line
                            ColumnLayout {
                                anchors.fill: parent
                                spacing: 0
                                TableTitle {
                                    Layout.fillWidth: true
                                    RowLayout { anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10; spacing: 10
                                        Text { Layout.fillWidth: true; text: "证书名称"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                        Text { Layout.preferredWidth: 170; text: "存储位置"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                        Text { Layout.preferredWidth: 100; text: "到期日"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                        Text { Layout.preferredWidth: 78; text: "状态"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    }
                                }
                                ListView {
                                    id: certificateList
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    clip: true
                                    model: App.certificates
                                    delegate: ItemDelegate {
                                        id: certificateRow
                                        required property string certificateId
                                        required property string name
                                        required property string issuer
                                        required property string scope
                                        required property string storeRole
                                        required property date expires
                                        required property int daysRemaining
                                        required property bool valid
                                        required property string fingerprint
                                        property bool apcmManaged: App.managedCertificates.some(function(item) { return item.fingerprint === fingerprint })
                                        width: certificateList.width
                                        height: visible ? 42 : 0
                                        visible: certificateSearch.text.length === 0 || name.toLowerCase().includes(certificateSearch.text.toLowerCase()) || issuer.toLowerCase().includes(certificateSearch.text.toLowerCase())
                                        contentItem: RowLayout { spacing: 10
                                            ColumnLayout { Layout.fillWidth: true; spacing: 0
                                                Text { Layout.fillWidth: true; text: name; color: Theme.text; elide: Text.ElideRight; font.family: Theme.uiFont; font.pixelSize: 11 }
                                                Text { Layout.fillWidth: true; text: issuer; color: Theme.textDim; elide: Text.ElideRight; font.family: Theme.uiFont; font.pixelSize: 9 }
                                            }
                                            Text { Layout.preferredWidth: 170; text: scope + " / " + storeRole; color: Theme.textMuted; elide: Text.ElideRight; font.family: Theme.uiFont; font.pixelSize: 10 }
                                            Text { Layout.preferredWidth: 100; text: Qt.formatDate(expires, "yyyy-MM-dd"); color: daysRemaining < 0 ? Theme.red : Theme.textMuted; font.family: Theme.uiFont; font.pixelSize: 10 }
                                            Text { Layout.preferredWidth: 78; text: apcmManaged ? "APCM 管理" : (valid ? "正常" : "需检查"); color: apcmManaged ? Theme.mint : (valid ? Theme.textMuted : Theme.amber); font.family: Theme.uiFont; font.pixelSize: 10 }
                                        }
                                        background: Rectangle { color: certificateRow.hovered ? "#EAF3FA" : "transparent"; border.width: 1; border.color: Theme.line }
                                        onClicked: { window.selectedCertificateId = certificateId; window.selectedDetails = App.certificateDetails(certificateId); detailsDrawer.open() }
                                    }
                                }
                            }
                        }
                    }
                }

                // Enrollment requests
                Item {
                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8
                        RowLayout {
                            Layout.fillWidth: true
                            SectionHeading { Layout.fillWidth: true; title: "证书申请"; subtitle: "创建真实 PKCS#10、导出 CSR 并安装签发证书" }
                            CommandButton { text: "新建申请…"; primary: true; onClicked: window.openRequestEditor("windows-user-client-auth", "自定义用户证书") }
                        }
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            color: Theme.panel
                            border.width: 1
                            border.color: Theme.line
                            ColumnLayout {
                                anchors.fill: parent
                                spacing: 0
                                TableTitle { Layout.fillWidth: true; RowLayout { anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10; spacing: 10
                                    Text { Layout.fillWidth: true; text: "申请名称 / 主题"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    Text { Layout.preferredWidth: 110; text: "状态"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    Text { Layout.preferredWidth: 90; text: "申请有效期"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    Text { Layout.preferredWidth: 244; text: "操作"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                } }
                                ListView {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    clip: true
                                    model: App.enrollmentRequests
                                    delegate: Rectangle {
                                        required property var modelData
                                        width: ListView.view.width
                                        height: 48
                                        color: "transparent"
                                        border.width: 1
                                        border.color: Theme.line
                                        RowLayout { anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10; spacing: 10
                                            ColumnLayout { Layout.fillWidth: true; spacing: 0
                                                Text { Layout.fillWidth: true; text: modelData.name || modelData.id; color: Theme.text; elide: Text.ElideRight; font.family: Theme.uiFont; font.pixelSize: 11 }
                                                Text { Layout.fillWidth: true; text: modelData.subject; color: Theme.textDim; elide: Text.ElideRight; font.family: Theme.uiFont; font.pixelSize: 9 }
                                            }
                                            Text { Layout.preferredWidth: 110; text: modelData.state; color: Theme.mint; font.family: Theme.uiFont; font.pixelSize: 10 }
                                            Text { Layout.preferredWidth: 90; text: modelData.validityDays + " 天"; color: Theme.textMuted; font.family: Theme.uiFont; font.pixelSize: 10 }
                                            RowLayout { Layout.preferredWidth: 244; spacing: 5
                                                CommandButton { text: "查看 CSR"; enabled: modelData.hasCsr; onClicked: { window.selectedRequestId = modelData.id; window.generatedCsr = App.requestCsr(modelData.id); csrDialog.open() } }
                                                CommandButton { text: "导出"; enabled: modelData.hasCsr; onClicked: { window.selectedRequestId = modelData.id; csrExportDialog.open() } }
                                                CommandButton { text: "安装证书…"; onClicked: { window.selectedRequestId = modelData.id; issuedCertificateDialog.open() } }
                                            }
                                        }
                                    }
                                    footer: Text { visible: App.enrollmentRequests.length === 0; width: parent ? parent.width : 0; topPadding: 24; text: "尚无申请。点击“新建申请”创建 Windows 持久密钥和真实 CSR。"; color: Theme.textDim; horizontalAlignment: Text.AlignHCenter; font.family: Theme.uiFont; font.pixelSize: 11 }
                                }
                            }
                        }
                    }
                }

                // Templates
                Item {
                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8
                        SectionHeading { title: "申请模板"; subtitle: "模板限定密钥提供程序与用途；创建时可编辑名称、主题、DNS 和申请有效期"; Layout.fillWidth: true }
                        Repeater {
                            model: App.templates
                            Rectangle {
                                required property var modelData
                                Layout.fillWidth: true
                                Layout.preferredHeight: 94
                                color: Theme.panel
                                border.width: 1
                                border.color: Theme.line
                                RowLayout { anchors.fill: parent; anchors.margins: 12; spacing: 14
                                    ColumnLayout { Layout.fillWidth: true; spacing: 2
                                        Text { text: modelData.name; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 12; font.bold: true }
                                        Text { text: modelData.provider; color: Theme.textMuted; font.family: Theme.uiFont; font.pixelSize: 10 }
                                        Text { text: modelData.scope + " · RSA " + modelData.bits + " 位 · " + (modelData.exportable ? "可导出" : "不可导出"); color: Theme.textDim; font.family: Theme.uiFont; font.pixelSize: 9 }
                                    }
                                    CommandButton { text: "使用模板…"; primary: true; onClicked: window.openRequestEditor(modelData.id, modelData.name) }
                                }
                            }
                        }
                        Text { text: "注意：PKCS#10 不包含最终证书过期时间。APCM 会保存用户申请的有效期，CA 在签发时决定最终有效期。"; color: Theme.amber; wrapMode: Text.WordWrap; font.family: Theme.uiFont; font.pixelSize: 10 }
                        Item { Layout.fillHeight: true }
                    }
                }

                // Managed roots
                Item {
                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8
                        RowLayout {
                            Layout.fillWidth: true
                            SectionHeading { Layout.fillWidth: true; title: "APCM 根证书"; subtitle: "选择 Windows 中已有的第三方根证书，由 APCM 跟踪管理" }
                            CommandButton { text: "从证书列表选择…"; primary: true; onClicked: window.pageIndex = 1 }
                            CommandButton { text: "安装新的根证书…"; onClicked: window.chooseCertificatePackage(1) }
                        }
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            color: Theme.panel
                            border.width: 1
                            border.color: Theme.line
                            ColumnLayout {
                                anchors.fill: parent
                                spacing: 0
                                TableTitle { Layout.fillWidth: true; RowLayout { anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10
                                    Text { Layout.fillWidth: true; text: "托管根证书"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    Text { Layout.preferredWidth: 130; text: "Windows 状态"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    Text { Layout.preferredWidth: 110; text: "操作"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                } }
                                ListView {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    model: App.managedRoots
                                    clip: true
                                    delegate: Rectangle {
                                        required property var modelData
                                        width: ListView.view.width
                                        height: 48
                                        color: "transparent"
                                        border.width: 1
                                        border.color: Theme.line
                                        RowLayout { anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10
                                            ColumnLayout { Layout.fillWidth: true; spacing: 0
                                                Text { text: modelData.name; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 11 }
                                                Text { Layout.fillWidth: true; text: modelData.fingerprint; elide: Text.ElideMiddle; color: Theme.textDim; font.family: Theme.uiFont; font.pixelSize: 9 }
                                            }
                                            Text { Layout.preferredWidth: 130; text: modelData.installed ? "已安装 / " + modelData.scope : "Windows 中已缺失"; color: modelData.installed ? Theme.mint : Theme.red; font.family: Theme.uiFont; font.pixelSize: 10 }
                                            CommandButton { Layout.preferredWidth: 110; text: "移出 APCM"; onClicked: App.unmanageRoot(modelData.fingerprint) }
                                        }
                                    }
                                    footer: Text { visible: App.managedRoots.length === 0; width: parent ? parent.width : 0; topPadding: 24; text: "尚未选择托管根证书。请到“证书”中打开受信任根证书，然后选择“加入 APCM 管理”。"; color: Theme.textDim; horizontalAlignment: Text.AlignHCenter; font.family: Theme.uiFont; font.pixelSize: 11 }
                                }
                            }
                        }
                    }
                }

                // Keys
                Item {
                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8
                        SectionHeading { title: "加密密钥"; subtitle: "从 Windows CNG/KSP 实时枚举的持久化私钥；APCM 不读取私钥材料"; Layout.fillWidth: true }
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            color: Theme.panel
                            border.width: 1
                            border.color: Theme.line
                            ColumnLayout {
                                anchors.fill: parent
                                spacing: 0
                                TableTitle { Layout.fillWidth: true; RowLayout { anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10; spacing: 10
                                    Text { Layout.fillWidth: true; text: "密钥容器"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    Text { Layout.preferredWidth: 260; text: "提供程序"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    Text { Layout.preferredWidth: 100; text: "算法"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    Text { Layout.preferredWidth: 100; text: "属性"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                } }
                                ListView {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    model: App.privateKeys
                                    clip: true
                                    delegate: Rectangle {
                                        required property var modelData
                                        width: ListView.view.width
                                        height: 42
                                        color: "transparent"
                                        border.width: 1
                                        border.color: Theme.line
                                        RowLayout { anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10; spacing: 10
                                            Text { Layout.fillWidth: true; text: modelData.container; elide: Text.ElideMiddle; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                                            Text { Layout.preferredWidth: 260; text: modelData.provider; elide: Text.ElideRight; color: Theme.textMuted; font.family: Theme.uiFont; font.pixelSize: 10 }
                                            Text { Layout.preferredWidth: 100; text: modelData.algorithm + " " + modelData.bits; color: Theme.textMuted; font.family: Theme.uiFont; font.pixelSize: 10 }
                                            Text { Layout.preferredWidth: 100; text: modelData.tpmBacked ? "TPM" : (modelData.hardwareBacked ? "硬件" : "软件"); color: modelData.tpmBacked ? Theme.mint : Theme.textMuted; font.family: Theme.uiFont; font.pixelSize: 10 }
                                        }
                                    }
                                    footer: ColumnLayout { visible: App.privateKeys.length === 0; width: parent ? parent.width : 0; spacing: 6
                                        Text { Layout.fillWidth: true; topPadding: 24; text: "未发现当前账户可枚举的 CNG 持久化密钥。"; color: Theme.text; horizontalAlignment: Text.AlignHCenter; font.family: Theme.uiFont; font.pixelSize: 11 }
                                        Text { Layout.fillWidth: true; text: "新建证书申请后会创建密钥；部分智能卡/HSM 会禁止静默枚举，机器密钥也可能需要管理员权限。"; color: Theme.textDim; horizontalAlignment: Text.AlignHCenter; wrapMode: Text.WordWrap; font.family: Theme.uiFont; font.pixelSize: 10 }
                                    }
                                }
                            }
                        }
                    }
                }

                // Audit log
                Item {
                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 14
                        spacing: 8
                        RowLayout {
                            Layout.fillWidth: true
                            SectionHeading { Layout.fillWidth: true; title: "审计日志"; subtitle: "最近 500 条本地操作记录，保存在 SQLCipher 加密保险库中" }
                            CommandButton { text: "刷新"; enabled: !App.busy; onClicked: App.refresh() }
                        }
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            color: Theme.panel
                            border.width: 1
                            border.color: Theme.line
                            ColumnLayout {
                                anchors.fill: parent
                                spacing: 0
                                TableTitle { Layout.fillWidth: true; RowLayout { anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10; spacing: 10
                                    Text { Layout.preferredWidth: 145; text: "时间"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    Text { Layout.preferredWidth: 150; text: "操作"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    Text { Layout.fillWidth: true; text: "目标"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    Text { Layout.preferredWidth: 130; text: "范围"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                    Text { Layout.preferredWidth: 54; text: "结果"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                                } }
                                ListView {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    model: App.auditEvents
                                    clip: true
                                    delegate: Rectangle {
                                        required property var modelData
                                        width: ListView.view.width
                                        height: 44
                                        color: "transparent"
                                        Rectangle { anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom; height: 1; color: Theme.line }
                                        RowLayout { anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10; spacing: 10
                                            Text { Layout.preferredWidth: 145; text: Qt.formatDateTime(modelData.timestamp, "yyyy-MM-dd HH:mm:ss"); color: Theme.textMuted; font.family: Theme.uiFont; font.pixelSize: 9 }
                                            Text { Layout.preferredWidth: 150; text: modelData.action; color: Theme.text; elide: Text.ElideRight; font.family: Theme.uiFont; font.pixelSize: 10 }
                                            ColumnLayout { Layout.fillWidth: true; spacing: 0
                                                Text { Layout.fillWidth: true; text: modelData.target; color: Theme.textMuted; elide: Text.ElideMiddle; font.family: Theme.uiFont; font.pixelSize: 9 }
                                                Text { Layout.fillWidth: true; visible: modelData.error.length > 0; text: modelData.error; color: Theme.red; elide: Text.ElideRight; font.family: Theme.uiFont; font.pixelSize: 8 }
                                            }
                                            Text { Layout.preferredWidth: 130; text: modelData.scope; color: Theme.textMuted; elide: Text.ElideRight; font.family: Theme.uiFont; font.pixelSize: 9 }
                                            Text { Layout.preferredWidth: 54; text: modelData.result; color: modelData.result === "成功" ? Theme.mint : Theme.red; font.family: Theme.uiFont; font.pixelSize: 9; font.bold: true }
                                        }
                                    }
                                    footer: Text { visible: App.auditEvents.length === 0; width: parent ? parent.width : 0; topPadding: 24; text: "尚无审计记录。"; color: Theme.textDim; horizontalAlignment: Text.AlignHCenter; font.family: Theme.uiFont; font.pixelSize: 11 }
                                }
                            }
                        }
                    }
                }
                IndependentSigningPage { Layout.fillWidth: true; Layout.fillHeight: true; onNavigateToCertificates: window.pageIndex = 1 }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 24
            color: "#F0F0F0"
            border.width: 1
            border.color: Theme.line
            RowLayout { anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8
                Text { text: App.statusMessage.length ? App.statusMessage : "就绪"; color: Theme.textMuted; font.family: Theme.uiFont; font.pixelSize: 9; elide: Text.ElideRight; Layout.fillWidth: true }
                Text { text: "APCM 0.1"; color: Theme.textDim; font.family: Theme.uiFont; font.pixelSize: 9 }
            }
        }
    }

    Drawer {
        id: detailsDrawer
        edge: Qt.RightEdge
        width: Math.min(500, window.width * 0.46)
        height: window.height
        background: Rectangle { color: Theme.panel; border.width: 1; border.color: Theme.lineBright }
        ScrollView {
            anchors.fill: parent
            contentWidth: availableWidth
            ColumnLayout {
                width: detailsDrawer.width
                spacing: 0
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 48
                    color: "#F0F0F0"
                    border.width: 1
                    border.color: Theme.line
                    RowLayout { anchors.fill: parent; anchors.leftMargin: 12; anchors.rightMargin: 8
                        Text { Layout.fillWidth: true; text: window.selectedDetails.name || "证书属性"; color: Theme.text; elide: Text.ElideRight; font.family: Theme.uiFont; font.pixelSize: 12; font.bold: true }
                        CommandButton { text: "关闭"; onClicked: detailsDrawer.close() }
                    }
                }
                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.margins: 14
                    spacing: 11
                    DetailField { label: "主题"; value: window.selectedDetails.subject || "—" }
                    DetailField { label: "颁发者"; value: window.selectedDetails.issuer || "—" }
                    DetailField { label: "存储位置"; value: (window.selectedDetails.scope || "") + " / " + (window.selectedDetails.store || "") }
                    DetailField { label: "有效期"; value: window.selectedDetails.notBefore ? Qt.formatDateTime(window.selectedDetails.notBefore, "yyyy-MM-dd") + " 至 " + Qt.formatDateTime(window.selectedDetails.notAfter, "yyyy-MM-dd") : "—" }
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 5
                        Text { text: "SHA-256 指纹"; color: Theme.textDim; font.family: Theme.uiFont; font.pixelSize: 9; font.weight: Font.Bold; font.letterSpacing: 0.8 }
                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8
                            Text { Layout.fillWidth: true; text: window.selectedDetails.sha256 || "—"; color: Theme.textMuted; wrapMode: Text.WrapAnywhere; font.family: "Consolas"; font.pixelSize: 10 }
                            CommandButton {
                                text: "复制"
                                enabled: (window.selectedDetails.sha256 || "").length > 0
                                onClicked: App.copyToClipboard(window.selectedDetails.sha256, "SHA-256 指纹")
                            }
                        }
                    }
                    Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: Theme.line }
                    DetailField { label: "私钥"; value: window.selectedDetails.hasPrivateKey ? "可用 / " + (window.selectedDetails.provider || "") : "没有关联私钥" }
                    DetailField { label: "硬件保护"; value: window.selectedDetails.tpmBacked ? "TPM" : (window.selectedDetails.hardwareBacked ? "硬件" : "否") }
                    DetailField { label: "APCM 管理"; value: window.selectedDetails.isManaged ? "是" : "否" }
                    CommandButton {
                        Layout.fillWidth: true
                        visible: window.selectedDetails.isRoot === true
                        primary: !window.selectedDetails.isManaged
                        text: window.selectedDetails.isManaged ? "已由 APCM 管理" : "加入 APCM 根证书管理"
                        enabled: !window.selectedDetails.isManaged
                        onClicked: { if (App.manageRoot(window.selectedCertificateId)) { window.selectedDetails = App.certificateDetails(window.selectedCertificateId) } }
                    }
                    CommandButton { Layout.fillWidth: true; text: "导出证书…"; onClicked: certificateExportDialog.open() }
                    Text { visible: window.selectedDetails.isRoot === true; Layout.fillWidth: true; text: "加入 APCM 只建立加密管理引用，不会复制或更改 Windows 根证书。"; color: Theme.textDim; wrapMode: Text.WordWrap; font.family: Theme.uiFont; font.pixelSize: 9 }
                    Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: Theme.line }
                    CommandButton { Layout.fillWidth: true; text: "删除证书…"; onClicked: deleteConfirm.open() }
                }
            }
        }
    }

    Dialog {
        id: requestEditor
        property string templateId: ""
        property string templateName: ""
        anchors.centerIn: parent
        width: Math.min(780, window.width - 48)
        height: Math.min(720, window.height - 48)
        modal: true
        title: "新建证书申请 - " + templateName
        standardButtons: Dialog.NoButton
        function createRequest() {
            App.clearMessage()
            var usages = []
            if (requestDigitalSignature.checked) usages.push("digitalSignature")
            if (requestKeyEncipherment.checked) usages.push("keyEncipherment")
            if (requestDataEncipherment.checked) usages.push("dataEncipherment")
            if (requestKeyAgreement.checked) usages.push("keyAgreement")
            if (requestNonRepudiation.checked) usages.push("nonRepudiation")
            var ekus = []
            if (requestClientAuth.checked) ekus.push("1.3.6.1.5.5.7.3.2")
            if (requestServerAuth.checked) ekus.push("1.3.6.1.5.5.7.3.1")
            if (requestCodeSigning.checked) ekus.push("1.3.6.1.5.5.7.3.3")
            if (requestEmailProtection.checked) ekus.push("1.3.6.1.5.5.7.3.4")
            var customEkus = requestCustomEku.text.split(/[,;\s]+/)
            for (var i = 0; i < customEkus.length; ++i) if (customEkus[i].length) ekus.push(customEkus[i])
            var result = App.generateRequest(templateId, {
                friendlyName: requestName.text,
                commonName: requestCn.text,
                organization: requestOrg.text,
                organizationUnit: requestOu.text,
                locality: requestLocality.text,
                state: requestState.text,
                country: requestCountry.text,
                dnsSans: requestDns.text,
                ipSans: requestIp.text,
                uriSans: requestUri.text,
                upnSans: requestUpn.text,
                scope: requestScope.currentIndex,
                provider: requestProvider.currentIndex === 1 ? "Microsoft Platform Crypto Provider" : "Microsoft Software Key Storage Provider",
                keyBits: Number(requestBits.currentText),
                exportable: requestProvider.currentIndex === 0 && requestExportable.checked,
                keyUsage: usages,
                extendedKeyUsage: ekus,
                validityDays: requestValidity.value
            })
            if (result.csr) {
                window.selectedRequestId = result.requestId
                window.generatedCsr = result.csr
                requestEditor.close()
                csrDialog.open()
            }
        }
        background: Rectangle { color: Theme.panel; border.width: 1; border.color: Theme.lineBright; radius: 2 }
        footer: Rectangle {
            implicitHeight: 46
            color: "#F3F3F3"
            border.width: 1
            border.color: Theme.line
            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 10
                anchors.rightMargin: 10
                Item { Layout.fillWidth: true }
                CommandButton { text: "取消"; onClicked: requestEditor.reject() }
                CommandButton { text: "生成 CSR"; primary: true; onClicked: requestEditor.createRequest() }
            }
        }
        contentItem: ScrollView {
            contentWidth: availableWidth
            ColumnLayout {
                width: requestEditor.availableWidth
                spacing: 10

                Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 27; color: "#F0F0F0"; border.width: 1; border.color: Theme.line
                    Text { anchors.left: parent.left; anchors.leftMargin: 8; anchors.verticalCenter: parent.verticalCenter; text: "标识与 X.500 主题"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                }
                GridLayout {
                    Layout.fillWidth: true
                    columns: 4
                    columnSpacing: 8
                    rowSpacing: 6
                    Text { text: "证书名称"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    EditBox { id: requestName; Layout.fillWidth: true; Layout.columnSpan: 3; placeholderText: "APCM 与 Windows 中显示的名称" }
                    Text { text: "通用名称（CN）*"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    EditBox { id: requestCn; Layout.fillWidth: true; Layout.columnSpan: 3; placeholderText: "client01.example.com" }
                    Text { text: "组织（O）"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    EditBox { id: requestOrg; Layout.fillWidth: true }
                    Text { text: "组织单位（OU）"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    EditBox { id: requestOu; Layout.fillWidth: true }
                    Text { text: "城市（L）"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    EditBox { id: requestLocality; Layout.fillWidth: true }
                    Text { text: "省/州（ST）"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    EditBox { id: requestState; Layout.fillWidth: true }
                    Text { text: "国家（C）"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    EditBox { id: requestCountry; Layout.preferredWidth: 110; placeholderText: "CN"; maximumLength: 2 }
                    Text { text: "期望有效期"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    SpinBox { id: requestValidity; Layout.preferredWidth: 140; from: 1; to: 3650; value: 365; editable: true; font.family: Theme.uiFont }
                }

                Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 27; color: "#F0F0F0"; border.width: 1; border.color: Theme.line
                    Text { anchors.left: parent.left; anchors.leftMargin: 8; anchors.verticalCenter: parent.verticalCenter; text: "主题备用名称（SAN）"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                }
                GridLayout {
                    Layout.fillWidth: true
                    columns: 2
                    columnSpacing: 8
                    rowSpacing: 6
                    Text { text: "DNS"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    EditBox { id: requestDns; Layout.fillWidth: true; placeholderText: "client01.example.com, client01" }
                    Text { text: "IP 地址"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    EditBox { id: requestIp; Layout.fillWidth: true; placeholderText: "192.0.2.10, 2001:db8::10" }
                    Text { text: "URI"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    EditBox { id: requestUri; Layout.fillWidth: true; placeholderText: "spiffe://example.com/workload" }
                    Text { text: "UPN"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    EditBox { id: requestUpn; Layout.fillWidth: true; placeholderText: "user@example.com" }
                }

                Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 27; color: "#F0F0F0"; border.width: 1; border.color: Theme.line
                    Text { anchors.left: parent.left; anchors.leftMargin: 8; anchors.verticalCenter: parent.verticalCenter; text: "Windows CNG 私钥"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                }
                GridLayout {
                    Layout.fillWidth: true
                    columns: 4
                    columnSpacing: 8
                    rowSpacing: 6
                    Text { text: "作用域"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    ComboBox { id: requestScope; Layout.fillWidth: true; model: ["当前用户", "本地计算机（需管理员权限）"]; font.family: Theme.uiFont }
                    Text { text: "RSA 长度"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    ComboBox { id: requestBits; Layout.preferredWidth: 120; model: ["2048", "3072", "4096"]; enabled: requestProvider.currentIndex === 0; font.family: Theme.uiFont }
                    Text { text: "密钥提供程序"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                    ComboBox {
                        id: requestProvider
                        Layout.fillWidth: true
                        Layout.columnSpan: 3
                        model: ["Microsoft Software Key Storage Provider", "Microsoft Platform Crypto Provider（TPM）"]
                        font.family: Theme.uiFont
                        onActivated: {
                            if (currentIndex === 1) {
                                requestBits.currentIndex = 0
                                requestExportable.checked = false
                            }
                        }
                    }
                    Item { Layout.preferredWidth: 1 }
                    CheckBox { id: requestExportable; Layout.columnSpan: 3; text: "允许导出私钥（仅软件 KSP）"; enabled: requestProvider.currentIndex === 0; font.family: Theme.uiFont }
                }
                Text { Layout.fillWidth: true; text: requestProvider.currentIndex === 1 ? "TPM 模式将私钥持久化在 Microsoft Platform Crypto Provider 中，强制不可导出；APCM 只保存容器引用。" : "软件 KSP 将私钥持久化在 Windows CNG 中；导出策略在创建密钥时写入。"; color: Theme.textMuted; wrapMode: Text.WordWrap; font.family: Theme.uiFont; font.pixelSize: 9 }

                Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 27; color: "#F0F0F0"; border.width: 1; border.color: Theme.line
                    Text { anchors.left: parent.left; anchors.leftMargin: 8; anchors.verticalCenter: parent.verticalCenter; text: "证书用途扩展"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                }
                Text { text: "Key Usage"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                Flow {
                    Layout.fillWidth: true
                    spacing: 10
                    CheckBox { id: requestDigitalSignature; text: "数字签名"; font.family: Theme.uiFont }
                    CheckBox { id: requestKeyEncipherment; text: "密钥加密"; font.family: Theme.uiFont }
                    CheckBox { id: requestDataEncipherment; text: "数据加密"; font.family: Theme.uiFont }
                    CheckBox { id: requestKeyAgreement; text: "密钥协商"; font.family: Theme.uiFont }
                    CheckBox { id: requestNonRepudiation; text: "不可否认性"; font.family: Theme.uiFont }
                }
                Text { text: "Enhanced Key Usage（EKU）"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                Flow {
                    Layout.fillWidth: true
                    spacing: 10
                    CheckBox { id: requestClientAuth; text: "客户端认证"; font.family: Theme.uiFont }
                    CheckBox { id: requestServerAuth; text: "服务器认证"; font.family: Theme.uiFont }
                    CheckBox { id: requestCodeSigning; text: "代码签名"; font.family: Theme.uiFont }
                    CheckBox { id: requestEmailProtection; text: "电子邮件保护"; font.family: Theme.uiFont }
                }
                EditBox { id: requestCustomEku; Layout.fillWidth: true; placeholderText: "自定义 EKU OID（可选，多个以逗号分隔）" }
                Text { Layout.fillWidth: true; text: "PKCS#10 不包含最终过期时间；期望有效期作为申请元数据保存，最终有效期由 CA 决定。签发证书安装时，APCM 会重新打开此密钥容器并核对公钥。"; color: Theme.amber; wrapMode: Text.WordWrap; font.family: Theme.uiFont; font.pixelSize: 9 }
            }
        }
    }

    Dialog {
        id: csrDialog
        anchors.centerIn: parent
        width: 720
        height: 570
        modal: true
        title: "PKCS#10 证书申请"
        standardButtons: Dialog.Close
        onOpened: standardButton(Dialog.Close).text = "关闭"
        background: Rectangle { color: Theme.panel; border.width: 1; border.color: Theme.lineBright; radius: 2 }
        contentItem: ColumnLayout {
            Text { Layout.fillWidth: true; text: "CSR 可复制或导出后交给 CA 签发；私钥保留在 Windows CNG 中。"; color: Theme.textMuted; wrapMode: Text.WordWrap; font.family: Theme.uiFont; font.pixelSize: 10 }
            TextArea { id: csrText; Layout.fillWidth: true; Layout.fillHeight: true; text: window.generatedCsr; readOnly: true; selectByMouse: true; wrapMode: TextEdit.WrapAnywhere; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 9; background: Rectangle { color: "#FAFAFA"; border.width: 1; border.color: Theme.lineBright; radius: 1 } }
            RowLayout {
                Layout.fillWidth: true
                Item { Layout.fillWidth: true }
                CommandButton {
                    text: "全选并复制"
                    onClicked: {
                        csrText.selectAll()
                        csrText.copy()
                    }
                }
            }
        }
    }

    FileDialog {
        id: certificateExportDialog
        title: "导出证书"
        fileMode: FileDialog.SaveFile
        defaultSuffix: "cer"
        nameFilters: ["DER 编码证书 (*.cer *.der)", "所有文件 (*)"]
        onAccepted: App.exportCertificate(window.selectedCertificateId, selectedFile)
    }

    FileDialog {
        id: csrExportDialog
        title: "导出 PKCS#10 证书申请"
        fileMode: FileDialog.SaveFile
        defaultSuffix: "csr"
        nameFilters: ["PKCS#10 证书申请 (*.csr *.pem)", "所有文件 (*)"]
        onAccepted: App.exportRequestCsr(window.selectedRequestId, selectedFile)
    }

    FileDialog {
        id: issuedCertificateDialog
        title: "选择 CA 返回的签发证书"
        nameFilters: ["X.509 证书 (*.cer *.crt *.der *.pem)", "所有文件 (*)"]
        onAccepted: App.installEnrollmentResponse(window.selectedRequestId, selectedFile)
    }

    FileDialog {
        id: certificatePackageFileDialog
        title: "选择证书或 PKCS#12 安装包"
        nameFilters: ["支持的证书 (*.pem *.crt *.cer *.der *.p12 *.pfx)", "PEM / CRT 证书 (*.pem *.crt *.cer *.der)", "PKCS#12 包 (*.p12 *.pfx)", "所有文件 (*)"]
        onAccepted: {
            App.clearMessage()
            window.selectedInstallFile = selectedFile
            var lowerName = selectedFile.toString().toLowerCase()
            window.packageIsPkcs12 = lowerName.endsWith(".p12") || lowerName.endsWith(".pfx")
            window.packagePreview = ({})
            installPassword.text = ""
            installScope.currentIndex = 0
            installStore.currentIndex = window.installDefaultRole
            rootInstallConfirm.checked = false
            if (!window.packageIsPkcs12)
                window.packagePreview = App.previewCertificatePackage(selectedFile, "")
            certificateInstallDialog.open()
        }
    }

    Dialog {
        id: certificateInstallDialog
        anchors.centerIn: parent
        width: 650
        height: 590
        modal: true
        title: "安装证书"
        standardButtons: Dialog.NoButton
        background: Rectangle { color: Theme.panel; border.width: 1; border.color: Theme.lineBright; radius: 2 }
        contentItem: ColumnLayout {
            spacing: 8
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 52
                color: "#F5F5F5"
                border.width: 1
                border.color: Theme.line
                ColumnLayout { anchors.fill: parent; anchors.margins: 8; spacing: 1
                    Text { Layout.fillWidth: true; text: window.selectedInstallFile.toString().split("/").pop(); color: Theme.text; elide: Text.ElideMiddle; font.family: Theme.uiFont; font.pixelSize: 11; font.bold: true }
                    Text { text: window.packageIsPkcs12 ? "PKCS#12：证书与私钥安装包" : "X.509 证书或 PEM 证书链"; color: Theme.textDim; font.family: Theme.uiFont; font.pixelSize: 9 }
                }
            }
            Text { visible: window.packageIsPkcs12; text: "P12 / PFX 密码"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
            RowLayout {
                Layout.fillWidth: true
                visible: window.packageIsPkcs12
                EditBox { id: installPassword; Layout.fillWidth: true; echoMode: TextInput.Password; placeholderText: "无密码时可留空" }
                CommandButton {
                    text: "检查内容"
                    onClicked: {
                        App.clearMessage()
                        window.packagePreview = App.previewCertificatePackage(window.selectedInstallFile, installPassword.text)
                    }
                }
            }
            GridLayout {
                Layout.fillWidth: true
                columns: 2
                columnSpacing: 10
                rowSpacing: 5
                Text { text: "作用域"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                ComboBox { id: installScope; Layout.fillWidth: true; model: ["当前用户", "本地计算机（需要管理员授权）"]; font.family: Theme.uiFont }
                Text { text: "证书存储"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10 }
                ComboBox { id: installStore; Layout.fillWidth: true; model: ["个人", "受信任的根 CA", "中间 CA", "企业信任"]; font.family: Theme.uiFont; onCurrentIndexChanged: rootInstallConfirm.checked = false }
            }
            Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: Theme.line }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 5
                Text { text: Object.keys(window.packagePreview).length ? "安装包内容" : "尚未验证安装包"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 10; font.bold: true }
                DetailField { label: "格式 / 数量"; value: window.packagePreview.format ? window.packagePreview.format + " / " + window.packagePreview.count + " 张" : "—" }
                DetailField { label: "首张证书"; value: window.packagePreview.name || "—" }
                DetailField { label: "颁发者"; value: window.packagePreview.issuer || "—" }
                DetailField { label: "SHA-256"; value: window.packagePreview.sha256 || "—"; mono: true }
            }
            CheckBox {
                id: rootInstallConfirm
                visible: installStore.currentIndex === 1
                Layout.fillWidth: true
                text: "我已独立核验根证书指纹，并确认更改 Windows 信任边界"
                font.family: Theme.uiFont
            }
            Text { Layout.fillWidth: true; text: "通过此窗口安装的每一张证书都会自动加入 APCM 加密管理清单。P12/PFX 密码不会保存到保险库或审计日志。"; color: Theme.mint; wrapMode: Text.WordWrap; font.family: Theme.uiFont; font.pixelSize: 9 }
            Item { Layout.fillHeight: true }
            RowLayout {
                Layout.fillWidth: true
                Item { Layout.fillWidth: true }
                CommandButton { text: "取消"; onClicked: { installPassword.text = ""; certificateInstallDialog.close() } }
                CommandButton {
                    text: "安装"
                    primary: true
                    enabled: Object.keys(window.packagePreview).length > 0 && (installStore.currentIndex !== 1 || rootInstallConfirm.checked)
                    onClicked: {
                        var packagePassword = installPassword.text
                        installPassword.text = ""
                        var result = App.installCertificatePackage(window.selectedInstallFile, packagePassword,
                            installScope.currentIndex, installStore.currentIndex, rootInstallConfirm.checked)
                        packagePassword = ""
                        if (result.success) certificateInstallDialog.close()
                    }
                }
            }
        }
    }

    Dialog {
        id: deleteConfirm
        anchors.centerIn: parent
        width: 480
        modal: true
        title: "删除证书"
        standardButtons: Dialog.Yes | Dialog.Cancel
        onOpened: { standardButton(Dialog.Yes).text = "删除"; standardButton(Dialog.Cancel).text = "取消" }
        onAccepted: if (App.deleteCertificate(window.selectedCertificateId, true)) detailsDrawer.close()
        background: Rectangle { color: Theme.panel; border.width: 1; border.color: Theme.lineBright; radius: 2 }
        contentItem: Text { text: "证书将从 Windows 证书存储移除，关联私钥不会被删除。"; color: Theme.textMuted; wrapMode: Text.WordWrap; font.family: Theme.uiFont; font.pixelSize: 11 }
    }

    Rectangle {
        visible: App.errorMessage.length > 0
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 34
        width: Math.min(640, errorText.implicitWidth + 40)
        height: Math.max(38, errorText.implicitHeight + 16)
        color: Theme.redWash
        border.width: 1
        border.color: Theme.red
        Text { id: errorText; anchors.centerIn: parent; width: parent.width - 24; text: App.errorMessage; color: Theme.red; wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignHCenter; font.family: Theme.uiFont; font.pixelSize: 10 }
        TapHandler { onTapped: App.clearMessage() }
    }

    Component.onCompleted: if (App.unlocked) App.refresh()
}

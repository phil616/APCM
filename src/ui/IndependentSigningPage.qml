import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import CertManager
import "components"

// qmllint disable unqualified

Item {
    id: root
    objectName: "independentSigningPage"
    property var service: App.signing
    property string selectedOperationId: ""
    property var selectedOperation: service.operations.find(function(op) { return op.id === root.selectedOperationId }) || ({})
    property var validation: selectedOperation.validation || ({})
    property string editingProfileId: ""
    signal navigateToCertificates()

    function clearSensitiveForms() {
        tokenInput.clear(); ownerPassword.clear(); holderTransport.password = ""; ownerTransport.password = ""; tokenDialog.secret = ""
        issueDialog.close(); tokenDialog.close(); ownerSettingsDialog.close(); instanceDialog.close(); credentialDialog.close()
        revokeDialog.close(); confirmDialog.close(); trackDialog.close(); csrPreview.close(); filePicker.close(); exportDialog.close()
        root.selectedOperationId = ""; root.editingProfileId = ""
    }
    function date(value) {
        if (!value) return "—"
        var parsed = new Date(value)
        return isNaN(parsed.getTime()) ? "—" : Qt.formatDateTime(parsed, "yyyy-MM-dd HH:mm")
    }
    function profileIndex() {
        return service.profiles.findIndex(function(p) { return p.id === service.selectedProfileId })
    }
    function currentInstance() {
        return service.ownerInstances.find(function(p) { return p.id === service.ownerInstanceId }) || ({})
    }
    function tokenExpirySummary(value) {
        var until = new Date(value)
        var days = Math.floor((until.getTime() - Date.now()) / 86400000)
        return days < 0 ? "Token 已过期（用户提供时间）" : "Token 约 " + days + " 天后到期（用户提供时间）"
    }
    function policySummary(policy) {
        function items(values) { return values && values.length ? values.join(", ") : "拒绝此类身份" }
        return "DNS 白名单：" + items(policy.allowed_dns_names) + "\n\nIP 范围：" + items(policy.allowed_ip_ranges)
            + "\n\n邮箱域名：" + items(policy.allowed_email_domains) + "\n\nURI 前缀：" + items(policy.allowed_uri_prefixes)
            + "\n\n证书用途：" + (policy.extended_key_usages || []).join(", ")
            + "\n\n有效期：默认 " + (policy.default_validity_seconds || "—") + " 秒 / 最大 " + (policy.max_validity_seconds || "—") + " 秒"
            + "\n\nSAN 上限：" + (policy.max_sans || "—") + " · 实际通配符证书：" + (policy.allow_wildcards ? "允许" : "禁止")
    }
    function loadProfile(profile) {
        editingProfileId = profile.id || ""
        profileName.text = profile.name || ""
        endpoint.text = profile.endpoint || ""
        tokenInput.clear()
        tokenExpiry.text = profile.tokenExpiresAt || ""
        scopeIssue.checked = (profile.scopes || ["issue", "read", "revoke"]).indexOf("issue") >= 0
        scopeRead.checked = (profile.scopes || ["issue", "read", "revoke"]).indexOf("read") >= 0
        scopeRevoke.checked = (profile.scopes || ["issue", "read", "revoke"]).indexOf("revoke") >= 0
        businessRoots.text = profile.businessRootsFile || ""
        holderTransport.load(profile)
    }
    function newIssue(previous) {
        issueDialog.previous = previous || ({})
        issueDialog.open()
    }
    function exportCertificate(part) {
        exportDialog.operationId = selectedOperationId
        exportDialog.part = part
        exportDialog.artifact = false
        exportDialog.nameFilters = ["PEM 证书 (*.pem *.crt)", "所有文件 (*)"]
        exportDialog.defaultSuffix = "pem"
        exportDialog.open()
    }
    function exportArtifact(kind) {
        exportDialog.artifact = true
        exportDialog.part = kind
        exportDialog.nameFilters = kind === "crl" ? ["DER CRL (*.crl)"] : kind === "issuer-pem" ? ["PEM CA (*.pem)"] : ["DER CA (*.cer)"]
        exportDialog.defaultSuffix = kind === "crl" ? "crl" : kind === "issuer-pem" ? "pem" : "cer"
        exportDialog.open()
    }
    component Action: Button {
        id: actionButton
        property bool primary: false
        property bool danger: false
        font.family: Theme.uiFont
        font.pixelSize: 11
        implicitHeight: 30
        leftPadding: 10; rightPadding: 10
        contentItem: Text { text: actionButton.text; color: actionButton.enabled ? (actionButton.primary ? "white" : actionButton.danger ? Theme.red : Theme.text) : Theme.textDim; font: actionButton.font; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter }
        background: Rectangle { color: actionButton.primary ? (actionButton.enabled ? Theme.mint : Theme.lineBright) : actionButton.hovered ? "#E8F0F8" : Theme.panel; border.color: actionButton.primary ? Theme.mint : Theme.lineBright; border.width: 1; radius: 2 }
    }
    component Caption: Label { textFormat: Text.PlainText; font.family: Theme.uiFont; font.pixelSize: 11; color: Theme.text }
    component Note: Label { textFormat: Text.PlainText; Layout.fillWidth: true; font.family: Theme.uiFont; font.pixelSize: 11; color: Theme.textMuted; wrapMode: Text.Wrap }
    component Panel: Pane {
        padding: 12
        background: Rectangle { color: Theme.panel; border.color: Theme.line; border.width: 1; radius: 2 }
    }

    ColumnLayout {
        anchors.fill: parent; anchors.margins: 14; spacing: 8
        SectionHeading { Layout.fillWidth: true; title: "AltasCI 证书管理"; subtitle: "独立签发端点 · 本地密钥与可恢复任务 · 通信 mTLS 独立配置" }
        TabBar {
            id: tabs; objectName: "tabs"; Layout.fillWidth: true
            TabButton { text: "证书与签发任务"; font.pixelSize: 12 }
            TabButton { text: "连接与凭据"; font.pixelSize: 12; onClicked: root.loadProfile(root.service.currentProfile) }
            TabButton { text: "实例所有者"; font.pixelSize: 12 }
        }
        Pane {
            Layout.fillWidth: true
            visible: root.service.errorMessage.length > 0 || root.service.statusMessage.length > 0
            padding: 8
            background: Rectangle { color: root.service.errorMessage.length ? "#FFF0EF" : Theme.mintWash; border.color: root.service.errorMessage.length ? Theme.red : Theme.line }
            RowLayout {
                anchors.fill: parent
                Label { Layout.fillWidth: true; text: root.service.errorMessage || root.service.statusMessage; color: root.service.errorMessage.length ? Theme.red : Theme.text; wrapMode: Text.WordWrap; font.pixelSize: 11; maximumLineCount: 6; elide: Text.ElideRight; textFormat: Text.PlainText }
                Action { text: "关闭"; onClicked: root.service.clearMessage() }
            }
        }
        StackLayout {
            Layout.fillWidth: true; Layout.fillHeight: true; currentIndex: tabs.currentIndex

            // Holder workbench: only local history, never a fictitious Bearer list endpoint.
            ColumnLayout {
                spacing: 8
                RowLayout {
                    Layout.fillWidth: true
                    Caption { text: "签发连接" }
                    ComboBox {
                        id: profilePicker; Layout.fillWidth: true; model: root.service.profiles; textRole: "name"; valueRole: "id"
                        currentIndex: root.profileIndex(); font.pixelSize: 11
                        onActivated: root.service.selectProfile(currentValue)
                    }
                    Action { text: "配置连接"; onClicked: { root.loadProfile(root.service.currentProfile); tabs.currentIndex = 1 } }
                    Action { text: "新建签发…"; primary: true; enabled: !root.service.busy && !!root.service.selectedProfileId; onClicked: root.newIssue({}) }
                    Action { text: "按 UUID 查询…"; enabled: !root.service.busy && !!root.service.selectedProfileId; onClicked: trackDialog.open() }
                }
                Note {
                    text: root.service.selectedProfileId ? root.service.currentProfile.endpoint + "\n" + root.service.transportSummary : "先添加公开签发端点和实例专属 Token；若入口要求 mTLS，请提前加载 HTTP 通信证书。"
                    font.pixelSize: 10
                }
                Note {
                    visible: !!root.service.currentProfile.tokenExpiresAt
                    text: root.tokenExpirySummary(root.service.currentProfile.tokenExpiresAt) + "：" + root.date(root.service.currentProfile.tokenExpiresAt) + "。Token 到期和证书到期分别管理，新的 Token 不接管旧证书权限。"
                    color: Theme.amber
                }
                SplitView {
                    Layout.fillWidth: true; Layout.fillHeight: true; orientation: Qt.Horizontal
                    Panel {
                        SplitView.fillWidth: true; SplitView.minimumWidth: 280
                        padding: 0
                        ColumnLayout {
                            anchors.fill: parent; spacing: 0
                            Rectangle {
                                Layout.fillWidth: true; Layout.preferredHeight: 32; color: Theme.ink
                                RowLayout { anchors.fill: parent; anchors.margins: 8
                                    Caption { text: "本地证书与任务"; font.bold: true; Layout.fillWidth: true }
                                    Caption { text: root.service.operations.length + " 条"; color: Theme.textDim }
                                }
                            }
                            ListView {
                                id: operationList; Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 0
                                model: root.service.operations
                                delegate: Rectangle {
                                    required property var modelData
                                    width: ListView.view.width; height: 84
                                    color: modelData.id === root.selectedOperationId ? "#E5F1FB" : operationMouse.containsMouse ? "#F7F9FC" : "transparent"
                                    border.width: 1; border.color: Theme.line
                                    ColumnLayout {
                                        anchors.fill: parent; anchors.margins: 9; spacing: 3
                                        Caption { Layout.fillWidth: true; text: modelData.name || modelData.id; font.bold: true; elide: Text.ElideRight }
                                        Caption { Layout.fillWidth: true; text: modelData.stateLabel; color: (modelData.state === "UNCERTAIN" || modelData.state === "REVOKE_PENDING" || modelData.state === "NEEDS_TRUST") ? Theme.amber : Theme.mint; elide: Text.ElideRight }
                                        Caption { Layout.fillWidth: true; text: modelData.validation ? "到期 " + root.date(modelData.validation.notAfter) + ((modelData.expiresInDays || 0) <= 7 ? " · 请检查续期" : "") : "创建 " + root.date(modelData.createdAt); color: Theme.textDim; font.pixelSize: 10; elide: Text.ElideRight }
                                    }
                                    MouseArea { id: operationMouse; anchors.fill: parent; hoverEnabled: true; onClicked: root.selectedOperationId = modelData.id }
                                }
                                Label { anchors.centerIn: parent; width: parent.width - 30; visible: operationList.count === 0; text: "尚无本地签发记录\n\n签发 API 不提供证书列表。任务、证书 UUID 与原凭据关系会保存在本地加密保险库。"; horizontalAlignment: Text.AlignHCenter; wrapMode: Text.WordWrap; color: Theme.textDim; font.pixelSize: 11 }
                            }
                        }
                    }
                    Panel {
                        SplitView.preferredWidth: 390; SplitView.minimumWidth: 320
                        ScrollView {
                            anchors.fill: parent; clip: true; contentWidth: availableWidth
                            ColumnLayout {
                                width: parent.width; spacing: 9
                                Caption { text: "任务详情"; font.bold: true; font.pixelSize: 14 }
                                Note { visible: !root.selectedOperationId; text: "从左侧选择任务，查看签发状态、证书身份和恢复操作。" }
                                ColumnLayout {
                                    Layout.fillWidth: true; visible: !!root.selectedOperationId; spacing: 8
                                    Note { text: root.selectedOperation.stateLabel || ""; color: Theme.mint; font.bold: true }
                                    Note { text: "连接：" + (root.selectedOperation.profileName || "—") + "\n" + (root.selectedOperation.endpoint || ""); font.pixelSize: 10 }
                                    Note { text: "Subject：" + (root.validation.subject || (root.selectedOperation.csrInfo || {}).subject || "—") }
                                    Note { text: "SAN：\n" + (root.validation.sans || (root.selectedOperation.csrInfo || {}).sans || []).join("\n") }
                                    Note { text: "用途：" + (root.validation.ekus || root.selectedOperation.expectedEkus || []).join(", ") }
                                    Note { text: "证书 UUID：" + (root.selectedOperation.certificateId || "尚未取得") + "\n序列号（十进制）：" + (root.validation.serial || "—"); font.pixelSize: 10 }
                                    Note { text: "SHA-256：" + (root.validation.fingerprint || "—"); font.pixelSize: 10 }
                                    Note { text: "有效期：" + root.date(root.validation.notBefore) + " → " + root.date(root.validation.notAfter) }
                                    Note { visible: !!root.selectedOperation.certificate; text: root.validation.chainTrusted ? "业务链：已通过可信根验证" : "业务链：尚未通过验证\n" + (root.validation.trustError || "请核对业务信任根"); color: root.validation.chainTrusted ? Theme.mint : Theme.amber }
                                    Note { visible: !!root.selectedOperation.certificate; text: root.selectedOperation.localRequestId ? "私钥：关联本地 CNG 申请；安装时再次核对公钥" : "私钥：未关联本地密钥，仅可导出给原私钥持有者" }
                                    Note { text: "HTTP：" + (root.selectedOperation.lastHttpStatus || "—") + "  问题码：" + (root.selectedOperation.lastProblemCode || "—") + "\n请求 ID：" + (root.selectedOperation.lastRequestId || "—") + "\n幂等键：" + (root.selectedOperation.idempotencyKey || "无；手动跟踪记录"); font.pixelSize: 10 }
                                    Note { visible: !!root.selectedOperation.retryAt; text: "可重试时间：" + root.date(root.selectedOperation.retryAt); color: Theme.amber }
                                    Note { visible: !!root.selectedOperation.lastError; text: root.selectedOperation.lastError || ""; color: Theme.red; textFormat: Text.PlainText }
                                    Flow {
                                        Layout.fillWidth: true; spacing: 6
                                        Action { text: "恢复原请求"; enabled: !root.service.busy && !!root.selectedOperation.requestBodyBase64; onClicked: root.service.retryOperation(root.selectedOperationId) }
                                        Action { text: "查询状态"; enabled: !root.service.busy && !!root.selectedOperation.certificateId; onClicked: root.service.refreshCertificate(root.selectedOperationId) }
                                        Action { text: "查看 CSR"; enabled: !!root.selectedOperation.csr; onClicked: csrPreview.open() }
                                        Action { text: "新任务续期…"; enabled: !root.service.busy; onClicked: root.newIssue(root.selectedOperation) }
                                        Action { text: "重新验证业务链"; enabled: !root.service.busy && !!root.selectedOperation.certificate; onClicked: root.service.revalidateOperation(root.selectedOperationId) }
                                        Action { text: "导出叶证书…"; enabled: !root.service.busy && !!root.selectedOperation.certificate; onClicked: root.exportCertificate("leaf") }
                                        Action { text: "导出完整链…"; enabled: !root.service.busy && !!root.selectedOperation.certificate; onClicked: root.exportCertificate("chain") }
                                        Action { text: "安装业务证书"; primary: true; enabled: !root.service.busy && root.validation.installable === true && !!root.selectedOperation.localRequestId && root.selectedOperation.pendingRevokeReason === undefined; onClicked: root.service.installOperation(root.selectedOperationId) }
                                        Action { text: root.selectedOperation.pendingRevokeReason !== undefined ? "恢复原原因吊销…" : "吊销证书…"; danger: true; enabled: !root.service.busy && !!root.selectedOperation.certificateId && !!root.validation.fingerprint; onClicked: revokeDialog.openHolder(root.selectedOperation) }
                                    }
                                    Note { text: "续期会创建新密钥、CSR 和幂等键。签发与导出不会自动安装证书、信任根或更新外部服务。"; font.pixelSize: 10 }
                                }
                            }
                        }
                    }
                }
            }

            // Connection editor and public diagnostics.
            ScrollView {
                clip: true; contentWidth: availableWidth
                ColumnLayout {
                    width: parent.width; spacing: 12
                    Panel {
                        Layout.fillWidth: true
                        ColumnLayout {
                            anchors.fill: parent; spacing: 8
                            RowLayout {
                                Layout.fillWidth: true
                                Caption { text: "签发连接与 Bearer 凭据"; font.bold: true; font.pixelSize: 14; Layout.fillWidth: true }
                                Action { text: "新建连接"; enabled: !root.service.busy; onClicked: root.loadProfile({}) }
                                Action { text: "编辑当前连接"; enabled: !root.service.busy && !!root.service.selectedProfileId; onClicked: root.loadProfile(root.service.currentProfile) }
                            }
                            GridLayout {
                                Layout.fillWidth: true; columns: 2; rowSpacing: 8; columnSpacing: 12
                                Caption { text: "连接名称" }
                                TextField { id: profileName; Layout.fillWidth: true; placeholderText: "例如：生产数据库证书"; font.pixelSize: 11 }
                                Caption { text: "完整签发端点" }
                                TextField { id: endpoint; Layout.fillWidth: true; placeholderText: "https://公开主机/signing/<实例 UUID>/issue"; font.pixelSize: 11 }
                                Caption { text: "签发 Token" }
                                TextField { id: tokenInput; Layout.fillWidth: true; echoMode: TextInput.Password; placeholderText: root.editingProfileId ? "留空保留原 Token；填写新 Token 将改变凭据绑定" : "ist_…（由实例所有者提供）"; font.pixelSize: 11 }
                                Caption { text: "Token 到期时间" }
                                TextField { id: tokenExpiry; Layout.fillWidth: true; placeholderText: "可选，例如 2026-12-17T12:00:00+08:00"; font.pixelSize: 11 }
                                Caption { text: "声明的 scopes" }
                                RowLayout { CheckBox { id: scopeIssue; text: "issue"; checked: true } CheckBox { id: scopeRead; text: "read"; checked: true } CheckBox { id: scopeRevoke; text: "revoke"; checked: true } }
                            }
                            Note { text: "到期时间和 scopes 由用户或所有者提供，仅用于提示；公开 API 无凭据信息或余额查询接口。Token 加密存于 Windows 凭据管理器，保险库仅记录其摘要。"; font.pixelSize: 10 }
                            SigningTransportFields { id: holderTransport; Layout.fillWidth: true }
                            Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: Theme.line }
                            Caption { text: "业务签发证书信任"; font.bold: true; font.pixelSize: 13 }
                            RowLayout {
                                Layout.fillWidth: true
                                TextField { id: businessRoots; Layout.fillWidth: true; readOnly: true; placeholderText: "可选：来自可信渠道的业务根 CA PEM；默认使用系统根"; font.pixelSize: 11 }
                                Action { text: "选择…"; onClicked: { filePicker.targetInput = businessRoots; filePicker.nameFilters = ["PEM CA (*.pem *.crt)"]; filePicker.open() } }
                                Action { text: "清空"; onClicked: businessRoots.clear() }
                            }
                            Note { text: "此根用于验证签发结果，与 HTTPS 服务器 CA 和通信 mTLS 身份分开。不会自动信任 /issuer.cer 下载内容，也不会更改 Windows 根证书库。"; color: Theme.amber; font.pixelSize: 10 }
                            RowLayout {
                                Layout.fillWidth: true
                                Action {
                                    text: "保存连接并加载通信身份"; primary: true; enabled: !root.service.busy
                                    onClicked: {
                                        var settings = holderTransport.configuration()
                                        settings.id = root.editingProfileId; settings.name = profileName.text; settings.endpoint = endpoint.text
                                        settings.tokenExpiresAt = tokenExpiry.text; settings.businessRootsFile = businessRoots.text
                                        settings.scopes = []; if (scopeIssue.checked) settings.scopes.push("issue"); if (scopeRead.checked) settings.scopes.push("read"); if (scopeRevoke.checked) settings.scopes.push("revoke")
                                        var saved = root.service.saveProfile(settings, tokenInput.text, holderTransport.password)
                                        tokenInput.clear(); holderTransport.password = ""
                                        if (saved) root.editingProfileId = root.service.selectedProfileId
                                    }
                                }
                                Item { Layout.fillWidth: true }
                                Action { text: "删除本地 Token…"; enabled: !root.service.busy && !!root.editingProfileId; danger: true; onClicked: { confirmDialog.action = "forget"; confirmDialog.targetId = root.editingProfileId; confirmDialog.message = "删除此连接在 Windows 凭据管理器中的 Token？原任务恢复、查询及吊销仍需要原 Token。此操作不会撤销服务端凭据或证书。"; confirmDialog.open() } }
                                Action { text: "删除连接…"; enabled: !root.service.busy && !!root.editingProfileId; onClicked: { confirmDialog.action = "delete-profile"; confirmDialog.targetId = root.editingProfileId; confirmDialog.message = "删除连接和本地 Token？有关联历史的连接会被保留。"; confirmDialog.open() } }
                            }
                            Note { text: "当前通信身份：" + root.service.transportSummary; color: Theme.mint; font.pixelSize: 10 }
                        }
                    }
                    Panel {
                        Layout.fillWidth: true
                        ColumnLayout {
                            anchors.fill: parent; spacing: 8
                            Caption { text: "公开诊断与撤销信息"; font.bold: true; font.pixelSize: 14 }
                            Note { text: "以下操作使用当前已保存的签发连接。下载 CA/CRL 不发送 Bearer Token，也不能验证 Token 是否有效；入口要求 mTLS 时仍须提供通信身份。" }
                            Flow {
                                Layout.fillWidth: true; spacing: 6
                                Action { text: "下载签发者 / 检测 HTTPS"; enabled: !root.service.busy && !!root.service.selectedProfileId; onClicked: root.service.fetchArtifact("issuer") }
                                Action { text: "下载并校验 CRL"; enabled: !root.service.busy && !!root.service.issuerInfo.subject; onClicked: root.service.fetchArtifact("crl") }
                                Action { text: "导出 CA DER…"; enabled: !!root.service.issuerInfo.subject; onClicked: root.exportArtifact("issuer") }
                                Action { text: "导出 CA PEM…"; enabled: !!root.service.issuerInfo.subject; onClicked: root.exportArtifact("issuer-pem") }
                                Action { text: "导出 CRL…"; enabled: !!root.service.crlInfo.issuer; onClicked: root.exportArtifact("crl") }
                            }
                            Note { visible: !!root.service.issuerInfo.subject; text: "签发者：" + (root.service.issuerInfo.subject || "") + "\nSHA-256：" + (root.service.issuerInfo.fingerprint || "") + "\n到期：" + root.date(root.service.issuerInfo.notAfter) }
                            Note { visible: !!root.service.crlInfo.issuer; text: "CRL：" + (root.service.crlInfo.count || 0) + " 条吊销记录 · 本次更新 " + root.date(root.service.crlInfo.thisUpdate) + " · 下次更新 " + root.date(root.service.crlInfo.nextUpdate) + "\n" + (root.service.crlInfo.note || "") }
                        }
                    }
                }
            }

            // Owner APIs have their own TLS configuration, Cookie jar and CSRF session.
            ColumnLayout {
                spacing: 8
                Panel {
                    Layout.fillWidth: true
                    ColumnLayout {
                        anchors.fill: parent; spacing: 6
                        RowLayout {
                            Layout.fillWidth: true
                            Caption { text: "实例所有者管理"; font.bold: true; font.pixelSize: 14; Layout.fillWidth: true }
                            Action { text: "配置管理端通信…"; enabled: !root.service.busy; onClicked: ownerSettingsDialog.open() }
                            Action { text: "检查会话"; visible: root.service.ownerAuthenticated; enabled: !root.service.busy; onClicked: root.service.ownerCheckSession() }
                            Action { text: "退出管理会话"; visible: root.service.ownerAuthenticated; enabled: !root.service.busy; onClicked: root.service.ownerLogout() }
                        }
                        Note { text: (root.service.ownerSettings.endpoint || "尚未配置 Console API：https://管理主机/api/v1") + "\n" + root.service.ownerTransportSummary; font.pixelSize: 10 }
                        RowLayout {
                            visible: !root.service.ownerAuthenticated; Layout.fillWidth: true
                            TextField { id: ownerLoginName; Layout.fillWidth: true; placeholderText: "所有者用户名 / 邮箱"; font.pixelSize: 11 }
                            TextField { id: ownerPassword; Layout.fillWidth: true; echoMode: TextInput.Password; placeholderText: "本地账户密码（仅本次登录）"; font.pixelSize: 11; onAccepted: { root.service.ownerLogin(ownerLoginName.text, text); clear() } }
                            Action { text: "登录"; primary: true; enabled: !root.service.busy && !!root.service.ownerSettings.endpoint; onClicked: { root.service.ownerLogin(ownerLoginName.text, ownerPassword.text); ownerPassword.clear() } }
                        }
                        Note { visible: root.service.ownerAuthenticated; text: "当前所有者：" + root.service.ownerUser + " · 会话到期：" + root.date(root.service.ownerSessionExpiry); color: Theme.mint }
                        Note { visible: !!root.service.ownerSettings.pendingCreate; text: "此前创建操作待核对：" + (root.service.ownerSettings.pendingCreate || "") + "。请先刷新实例/凭据列表，不要直接重建。"; color: Theme.amber }
                        Action { visible: !!root.service.ownerSettings.pendingCreate; text: "已核对历史，确认后继续…"; enabled: !root.service.busy; onClicked: { confirmDialog.action = "acknowledge"; confirmDialog.message = "确认已刷新并核对实例/凭据历史？创建响应丢失的 Token 明文无法找回，应先撤销该凭据再新建。"; confirmDialog.open() } }
                    }
                }
                RowLayout {
                    Layout.fillWidth: true; visible: root.service.ownerAuthenticated
                    ComboBox {
                        id: ownerInstancePicker; Layout.fillWidth: true; model: root.service.ownerInstances; textRole: "name"; valueRole: "id"; font.pixelSize: 11
                        currentIndex: root.service.ownerInstances.findIndex(function(p) { return p.id === root.service.ownerInstanceId })
                        onActivated: root.service.ownerSelectInstance(currentValue)
                    }
                    Action { text: "刷新实例"; enabled: !root.service.busy; onClicked: root.service.ownerRefreshInstances() }
                    Action { text: "导入 CA / 新实例…"; enabled: !root.service.busy; onClicked: { instanceDialog.editing = false; instanceDialog.open() } }
                }
                TabBar {
                    id: ownerTabs; objectName: "ownerTabs"; Layout.fillWidth: true; visible: root.service.ownerAuthenticated
                    TabButton { text: "实例与策略" }
                    TabButton { text: "签发凭据"; onClicked: if (root.service.ownerInstanceId) root.service.ownerRefreshCredentials() }
                    TabButton { text: "证书历史"; onClicked: if (root.service.ownerInstanceId) root.service.ownerLoadCertificates(false) }
                }
                StackLayout {
                    Layout.fillWidth: true; Layout.fillHeight: true; visible: root.service.ownerAuthenticated; currentIndex: ownerTabs.currentIndex
                    Panel {
                        ScrollView { anchors.fill: parent; clip: true; contentWidth: availableWidth
                            ColumnLayout {
                                width: parent.width; spacing: 10
                                Caption { text: root.currentInstance().name || "请选择实例，或导入专用 CA 创建实例"; font.bold: true; font.pixelSize: 14 }
                                Note { text: "实例 UUID：" + (root.currentInstance().id || "—") + "\n签发端点：" + (root.currentInstance().endpoint || "—") }
                                Note { text: "新签发：" + (root.currentInstance().enabled ? "已启用" : "已停用") + " · CA 到期：" + root.date(root.currentInstance().not_after) }
                                Note { text: root.policySummary(root.currentInstance().policy || {}); font.family: Theme.uiFont; font.pixelSize: 11 }
                                Action { text: "刷新当前实例详情"; enabled: !root.service.busy && !!root.service.ownerInstanceId; onClicked: root.service.ownerRefreshInstance() }
                                Action { text: "修改名称、完整策略及启用状态…"; enabled: !root.service.busy && !!root.service.ownerInstanceId; onClicked: { instanceDialog.editing = true; instanceDialog.open() } }
                                Note { text: "修改策略或停用实例不自动吊销已有证书。更换 CA 材料须创建新实例；超级管理员也只管理自己拥有的实例。"; color: Theme.amber }
                            }
                        }
                    }
                    Panel {
                        ColumnLayout {
                            anchors.fill: parent; spacing: 8
                            RowLayout { Layout.fillWidth: true
                                Caption { Layout.fillWidth: true; text: "凭据元数据 · Token 明文只在创建时显示一次"; font.bold: true }
                                Action { text: "刷新"; enabled: !root.service.busy && !!root.service.ownerInstanceId; onClicked: root.service.ownerRefreshCredentials() }
                                Action { text: "创建 Token…"; enabled: !root.service.busy && !!root.service.ownerInstanceId; onClicked: credentialDialog.open() }
                            }
                            ListView {
                                Layout.fillWidth: true; Layout.fillHeight: true; clip: true; model: root.service.ownerCredentials; spacing: 6
                                delegate: Pane {
                                    required property var modelData
                                    width: ListView.view.width; padding: 8
                                    background: Rectangle { color: Theme.ink; border.color: Theme.line }
                                    RowLayout {
                                        anchors.fill: parent
                                        ColumnLayout { Layout.fillWidth: true; spacing: 4
                                            Caption { text: modelData.name + (modelData.revoked_at ? " · 已撤销" : ""); font.bold: true }
                                            Note { text: (modelData.scopes || []).join(", ") + " · 累计 " + modelData.issued_count + "/" + modelData.max_issuances + " · 每分钟 " + modelData.rate_per_minute }
                                            Note { text: "到期：" + root.date(modelData.expires_at) + "\nID：" + modelData.id; font.pixelSize: 10 }
                                        }
                                        Action { text: "撤销 Token…"; danger: true; enabled: !root.service.busy && !modelData.revoked_at; onClicked: { confirmDialog.action = "revoke-token"; confirmDialog.targetId = modelData.id; confirmDialog.message = "撤销签发凭据“" + modelData.name + "”？它将无法再签发、读取、吊销或恢复请求；此前的叶证书不会自动吊销。"; confirmDialog.open() } }
                                    }
                                }
                                footer: Note { width: parent ? parent.width : 0; visible: root.service.ownerCredentials.length === 0; text: "点击刷新读取凭据元数据；Token 明文无法从列表找回。" }
                            }
                        }
                    }
                    Panel {
                        ColumnLayout {
                            anchors.fill: parent; spacing: 8
                            RowLayout { Layout.fillWidth: true
                                Caption { Layout.fillWidth: true; text: "实例全部签发历史（每页 100 条）"; font.bold: true }
                                Action { text: "刷新首页"; enabled: !root.service.busy && !!root.service.ownerInstanceId; onClicked: root.service.ownerLoadCertificates(false) }
                                Action { text: "加载下一页"; enabled: !root.service.busy && !!root.service.ownerNextCursor; onClicked: root.service.ownerLoadCertificates(true) }
                            }
                            ListView {
                                Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 6; model: root.service.ownerCertificates
                                delegate: Pane {
                                    required property var modelData
                                    width: ListView.view.width; padding: 8
                                    background: Rectangle { color: Theme.ink; border.color: Theme.line }
                                    RowLayout {
                                        anchors.fill: parent
                                        ColumnLayout { Layout.fillWidth: true; spacing: 4
                                            Note { text: (modelData.details || {}).subject || modelData.id; font.bold: true }
                                            Note { text: modelData.status + " · 到期 " + root.date(modelData.not_after) + "\nUUID：" + modelData.id + "\n序列号：" + modelData.serial; font.pixelSize: 10 }
                                            Note { text: "SHA-256：" + modelData.fingerprint_sha256; font.pixelSize: 10 }
                                        }
                                        Action { text: "吊销…"; danger: true; enabled: !root.service.busy && modelData.status !== "revoked"; onClicked: revokeDialog.openOwner(modelData) }
                                    }
                                }
                            }
                        }
                    }
                }
                Item { Layout.fillHeight: true; visible: !root.service.ownerAuthenticated }
            }
        }
        ProgressBar { Layout.fillWidth: true; visible: root.service.busy; indeterminate: true; Layout.preferredHeight: 3 }
    }

    Dialog {
        id: issueDialog
        objectName: "issueDialog"
        property var previous: ({})
        anchors.centerIn: parent; width: Math.min(790, root.width - 20); height: Math.min(730, root.height - 20)
        modal: true; title: previous.id ? "新建续期任务（生成新密钥与 CSR）" : "创建独立签发任务"
        onOpened: {
            var info = previous.csrInfo || {}
            issueMode.currentIndex = 0
            issueName.text = previous.name ? previous.name + "（续期）" : "AltasCI 业务证书"
            subjectCn.text = info.CN || ""; subjectCountry.text = info.C || ""; subjectState.text = info.ST || ""
            subjectCity.text = info.L || ""; subjectOrg.text = info.O || ""; subjectOu.text = info.OU || ""
            dnsSans.text = (info.dnsSans || []).join("\n"); ipSans.text = (info.ipSans || []).join("\n")
            emailSans.text = (info.emailSans || []).join("\n"); uriSans.text = (info.uriSans || []).join("\n")
            requestedValidity.value = previous.validitySeconds || 0
            expectedServer.checked = !previous.id || (previous.expectedEkus || []).indexOf("server_auth") >= 0
            expectedClient.checked = (previous.expectedEkus || []).indexOf("client_auth") >= 0
            csrFile.text = ""; csrPaste.clear(); issueAlgorithm.currentIndex = 0; importedKey.currentIndex = 0
        }
        contentItem: ScrollView {
            clip: true; contentWidth: availableWidth
            ColumnLayout {
                width: parent.width; spacing: 10
                Note { text: "目标：" + (root.service.currentProfile.endpoint || ""); font.pixelSize: 10 }
                Note { visible: root.service.errorMessage.length > 0; text: root.service.errorMessage; color: Theme.red; textFormat: Text.PlainText }
                RowLayout {
                    Layout.fillWidth: true
                    Caption { text: "证书名称" }
                    TextField { id: issueName; Layout.fillWidth: true; font.pixelSize: 11 }
                    ComboBox { id: issueMode; model: ["本地生成 CSR 后签发", "导入外部 CSR", "使用本地申请"]; font.pixelSize: 11 }
                }
                ColumnLayout {
                    Layout.fillWidth: true; visible: issueMode.currentIndex === 0
                    GridLayout {
                        Layout.fillWidth: true; columns: 4; columnSpacing: 8; rowSpacing: 6
                        Caption { text: "CN" } TextField { id: subjectCn; Layout.fillWidth: true; placeholderText: "可为空；非空时必须等于一个 SAN"; font.pixelSize: 11 }
                        Caption { text: "C" } TextField { id: subjectCountry; Layout.fillWidth: true; placeholderText: "两位大写国家代码"; maximumLength: 2; font.pixelSize: 11 }
                        Caption { text: "ST" } TextField { id: subjectState; Layout.fillWidth: true; placeholderText: "省 / 州"; font.pixelSize: 11 }
                        Caption { text: "L" } TextField { id: subjectCity; Layout.fillWidth: true; placeholderText: "城市"; font.pixelSize: 11 }
                        Caption { text: "O" } TextField { id: subjectOrg; Layout.fillWidth: true; placeholderText: "组织"; font.pixelSize: 11 }
                        Caption { text: "OU" } TextField { id: subjectOu; Layout.fillWidth: true; placeholderText: "部门"; font.pixelSize: 11 }
                    }
                    Note { text: "服务端只接收 CSR。本机会先创建 CNG 私钥及标准 PKCS#10，再提交 CSR；SAN 至少填写一项，CN 不会自动改写。" }
                    GridLayout {
                        Layout.fillWidth: true; columns: 2; columnSpacing: 10; rowSpacing: 5
                        Caption { text: "DNS SAN" } Caption { text: "IP SAN" }
                        ScrollView { Layout.fillWidth: true; Layout.preferredHeight: 65; TextArea { id: dnsSans; placeholderText: "db.example.com"; font.pixelSize: 11; wrapMode: TextEdit.Wrap } }
                        ScrollView { Layout.fillWidth: true; Layout.preferredHeight: 65; TextArea { id: ipSans; placeholderText: "10.20.0.5\n2001:db8::1"; font.pixelSize: 11; wrapMode: TextEdit.Wrap } }
                        Caption { text: "email SAN" } Caption { text: "URI SAN" }
                        ScrollView { Layout.fillWidth: true; Layout.preferredHeight: 65; TextArea { id: emailSans; placeholderText: "service@example.com"; font.pixelSize: 11; wrapMode: TextEdit.Wrap } }
                        ScrollView { Layout.fillWidth: true; Layout.preferredHeight: 65; TextArea { id: uriSans; placeholderText: "spiffe://example.com/workloads/db"; font.pixelSize: 11; wrapMode: TextEdit.Wrap } }
                    }
                    RowLayout {
                        Caption { text: "密钥算法" }
                        ComboBox { id: issueAlgorithm; model: ["ECDSA P-256", "ECDSA P-384", "RSA 2048", "RSA 3072", "RSA 4096"]; font.pixelSize: 11 }
                        Note { text: "当前用户 CNG 软件密钥库 · 新私钥不可导出且不上传"; font.pixelSize: 10 }
                    }
                }
                ColumnLayout {
                    Layout.fillWidth: true; visible: issueMode.currentIndex === 1
                    RowLayout { Layout.fillWidth: true
                        TextField { id: csrFile; Layout.fillWidth: true; readOnly: true; placeholderText: "选择单个 PKCS#10 CSR，最大 64 KiB"; font.pixelSize: 11 }
                        Action { text: "选择 CSR…"; onClicked: { filePicker.targetInput = csrFile; filePicker.nameFilters = ["PKCS#10 CSR (*.csr *.pem)"]; filePicker.open() } }
                        Action { text: "清空"; onClicked: csrFile.clear() }
                    }
                    ScrollView { Layout.fillWidth: true; Layout.preferredHeight: 150; TextArea { id: csrPaste; placeholderText: "也可粘贴标准 CERTIFICATE REQUEST PEM；已选择文件时优先读取文件。"; font.pixelSize: 11; wrapMode: TextEdit.Wrap } }
                    Caption { text: "可选：关联已存在的当前用户 CNG 私钥（安装时核对公钥）" }
                    ComboBox {
                        id: importedKey; Layout.fillWidth: true; textRole: "label"; font.pixelSize: 11
                        model: [{label: "不关联本地私钥；仅导出证书", provider: "", container: ""}].concat(App.privateKeys.filter(function(k) { return !k.machineKey }).map(function(k) { return {label: k.provider + " / " + k.container, provider: k.provider, container: k.container} }))
                    }
                    RowLayout { Note { text: "已有私钥可先通过应用的 P12/PFX 安装功能导入，再选择对应 CNG 容器。单凭 CSR 不表示持有私钥。"; font.pixelSize: 10 } Action { text: "前往证书管理"; onClicked: { issueDialog.close(); root.navigateToCertificates() } } }
                }
                ComboBox { id: localRequest; Layout.fillWidth: true; visible: issueMode.currentIndex === 2; model: App.enrollmentRequests; textRole: "name"; valueRole: "id"; font.pixelSize: 11 }
                Note { visible: issueMode.currentIndex === 2; text: "本地申请仍需通过 SAN-only 校验；含 KU/EKU 或 UPN 的传统申请无法用于此协议。"; color: Theme.amber }
                RowLayout {
                    Caption { text: "有效期 / 秒" }
                    SpinBox { id: requestedValidity; from: 0; to: 34300800; value: 0; editable: true }
                    Note { text: "0 使用服务端默认；否则至少 60 秒，最多 397 天，并受 CA/Token 策略约束。"; font.pixelSize: 10 }
                }
                RowLayout {
                    Caption { text: "预期用途" }
                    CheckBox { id: expectedServer; text: "server_auth"; checked: true }
                    CheckBox { id: expectedClient; text: "client_auth" }
                }
                Note { text: "预期用途仅用于核验响应，不能覆盖实例或 Token 策略。点击后先保存完整请求和幂等键，再发送；失败时应在原任务中恢复。"; color: Theme.amber; font.pixelSize: 10 }
            }
        }
        footer: DialogButtonBox {
            Action { text: "取消"; DialogButtonBox.buttonRole: DialogButtonBox.RejectRole; onClicked: issueDialog.close() }
            Action {
                text: "保存并签发"; primary: true; enabled: !root.service.busy; DialogButtonBox.buttonRole: DialogButtonBox.AcceptRole
                onClicked: {
                    var options = {renewFrom: issueDialog.previous.id || "", name: issueName.text, validitySeconds: requestedValidity.value, expectedEkus: []}
                    if (expectedServer.checked) options.expectedEkus.push("server_auth")
                    if (expectedClient.checked) options.expectedEkus.push("client_auth")
                    if (issueMode.currentIndex === 0) {
                        options.CN = subjectCn.text; options.C = subjectCountry.text; options.ST = subjectState.text
                        options.L = subjectCity.text; options.O = subjectOrg.text; options.OU = subjectOu.text
                        options.dnsSans = dnsSans.text; options.ipSans = ipSans.text; options.emailSans = emailSans.text; options.uriSans = uriSans.text
                        options.algorithm = ["ECDSA_P256", "ECDSA_P384", "RSA2048", "RSA3072", "RSA4096"][issueAlgorithm.currentIndex]
                    } else if (issueMode.currentIndex === 1) {
                        options.csrFile = csrFile.text; options.csr = csrPaste.text
                        var key = importedKey.model[importedKey.currentIndex] || {}
                        options.provider = key.provider || ""; options.keyContainer = key.container || ""
                        if (!options.csrFile && !options.csr) return
                    } else {
                        if (localRequest.currentIndex < 0) return
                        options.localRequestId = localRequest.currentValue
                    }
                    var id = root.service.prepareIssue(options)
                    if (id) { root.selectedOperationId = id; issueDialog.close(); tabs.currentIndex = 0; root.service.retryOperation(id) }
                }
            }
        }
    }
    Dialog {
        id: trackDialog; objectName: "trackDialog"; anchors.centerIn: parent; width: Math.min(490, root.width - 20); modal: true; title: "查询原凭据签发的证书"
        standardButtons: Dialog.Ok | Dialog.Cancel
        onOpened: { trackUuid.clear(); standardButton(Dialog.Ok).text = "查询"; standardButton(Dialog.Cancel).text = "取消" }
        onAccepted: root.service.trackCertificate(trackUuid.text.trim())
        contentItem: ColumnLayout {
            Note { text: "输入已知证书 UUID；不存在域名检索或 Bearer 列表接口。必须使用原 Token，404 也可能表示该凭据无权查看。" }
            TextField { id: trackUuid; Layout.fillWidth: true; placeholderText: "证书 UUID" }
        }
    }
    Dialog {
        id: csrPreview; anchors.centerIn: parent; width: Math.min(670, root.width - 20); height: Math.min(450, root.height - 20); modal: true; title: "本地 PKCS#10 CSR（公开申请材料）"
        standardButtons: Dialog.Close
        onOpened: standardButton(Dialog.Close).text = "关闭"
        contentItem: ScrollView { TextArea { text: root.selectedOperation.csr || ""; readOnly: true; selectByMouse: true; wrapMode: TextEdit.Wrap; font.pixelSize: 11 } }
    }
    Dialog {
        id: revokeDialog
        objectName: "revokeDialog"
        property bool owner: false
        property string targetId: ""
        property var details: ({})
        property int originalReason: -1
        function openHolder(operation) {
            owner = false; targetId = operation.id; details = operation.validation || operation.csrInfo || {}
            originalReason = operation.pendingRevokeReason === undefined ? -1 : operation.pendingRevokeReason
            open()
        }
        function openOwner(record) {
            owner = true; targetId = record.id; details = record.details || {}
            var pending = root.service.ownerSettings.pendingRevocations || {}
            var reason = pending[root.service.ownerInstanceId + "/" + record.id]
            originalReason = reason === undefined ? -1 : reason
            open()
        }
        anchors.centerIn: parent; width: Math.min(620, root.width - 20); modal: true; title: "确认不可逆吊销"
        standardButtons: Dialog.Ok | Dialog.Cancel
        onOpened: {
            reasonChoice.currentIndex = originalReason < 0 ? 1 : reasonChoice.model.findIndex(function(r) { return r.code === revokeDialog.originalReason })
            standardButton(Dialog.Ok).text = "确认吊销"; standardButton(Dialog.Cancel).text = "取消"
        }
        onAccepted: {
            var reason = reasonChoice.model[reasonChoice.currentIndex].code
            if (owner) root.service.ownerRevokeCertificate(targetId, reason, true)
            else root.service.revokeCertificate(targetId, reason, true)
        }
        contentItem: ColumnLayout {
            Note { text: "此操作不可恢复，包括原因 6。请确认目标身份、指纹和原因。"; color: Theme.red }
            Note { text: "Subject：" + (revokeDialog.details.subject || "—") + "\nSAN：" + (revokeDialog.details.sans || []).join(", ") }
            Note { text: "序列号：" + (revokeDialog.details.serial || "—") + "\nSHA-256：" + (revokeDialog.details.fingerprint || "—") + "\n记录：" + revokeDialog.targetId; font.pixelSize: 10 }
            ComboBox {
                id: reasonChoice; Layout.fillWidth: true; textRole: "label"; enabled: revokeDialog.originalReason < 0
                model: [{code: 0, label: "0 · 未指定"}, {code: 1, label: "1 · 私钥泄露或失控"}, {code: 2, label: "2 · CA 密钥泄露"}, {code: 3, label: "3 · 隶属关系变化"}, {code: 4, label: "4 · 已被新证书替代"}, {code: 5, label: "5 · 停止使用"}, {code: 6, label: "6 · certificateHold（本接口仍不可恢复）"}, {code: 9, label: "9 · 权限取消"}, {code: 10, label: "10 · 属性授权机构泄露"}]
            }
            Note { visible: revokeDialog.originalReason >= 0; text: "此前吊销结果待确认，已锁定原原因码；同原因请求可安全恢复。"; color: Theme.amber }
        }
    }
    Dialog {
        id: confirmDialog
        property string action: ""
        property string targetId: ""
        property string message: ""
        anchors.centerIn: parent; width: Math.min(510, root.width - 20); modal: true; title: "确认操作"
        standardButtons: Dialog.Ok | Dialog.Cancel
        onOpened: { standardButton(Dialog.Ok).text = "确认"; standardButton(Dialog.Cancel).text = "取消" }
        contentItem: Note { text: confirmDialog.message; color: Theme.amber }
        onAccepted: {
            if (action === "forget") root.service.forgetToken(targetId, true)
            else if (action === "delete-profile") { if (root.service.deleteProfile(targetId, true)) root.loadProfile({}) }
            else if (action === "revoke-token") root.service.ownerRevokeCredential(targetId, true)
            else if (action === "acknowledge") root.service.ownerAcknowledgePending(true)
        }
    }
    Dialog {
        id: ownerSettingsDialog; objectName: "ownerSettingsDialog"; anchors.centerIn: parent; width: Math.min(760, root.width - 20); height: Math.min(650, root.height - 20); modal: true; title: "所有者管理端 · 独立通信配置"
        onOpened: { ownerEndpoint.text = root.service.ownerSettings.endpoint || ""; ownerTransport.load(root.service.ownerSettings) }
        onClosed: ownerTransport.password = ""
        contentItem: ScrollView { clip: true; contentWidth: availableWidth
            ColumnLayout { width: parent.width; spacing: 10
                Note { text: "此连接访问 Console API，不使用签发 Token。与公开端点分别加载通信 mTLS 身份；账户密码仅用于登录，Cookie 与 CSRF 仅留在内存。" }
                TextField { id: ownerEndpoint; Layout.fillWidth: true; placeholderText: "https://管理主机/api/v1"; font.pixelSize: 11 }
                SigningTransportFields { id: ownerTransport; Layout.fillWidth: true }
                Note { visible: root.service.errorMessage.length > 0; text: root.service.errorMessage; color: Theme.red }
            }
        }
        footer: DialogButtonBox {
            Action { text: "取消"; onClicked: ownerSettingsDialog.close() }
            Action { text: "保存并加载通信身份"; primary: true; enabled: !root.service.busy; onClicked: {
                var settings = ownerTransport.configuration(); settings.endpoint = ownerEndpoint.text
                var saved = root.service.saveOwnerSettings(settings, ownerTransport.password); ownerTransport.password = ""
                if (saved) ownerSettingsDialog.close()
            } }
        }
    }
    Dialog {
        id: instanceDialog
        objectName: "instanceDialog"
        property bool editing: false
        anchors.centerIn: parent; width: Math.min(790, root.width - 20); height: Math.min(750, root.height - 20); modal: true; title: editing ? "修改完整实例策略" : "导入独立 CA 并创建实例"
        onOpened: {
            var instance = editing ? root.currentInstance() : {}
            instanceName.text = instance.name || ""; instanceEnabled.checked = instance.enabled !== false
            instancePolicy.load(instance.policy || {}); caCertificate.clear(); caPrivateKey.clear(); caChain.clear(); uploadConfirmation.checked = false
        }
        contentItem: ScrollView { clip: true; contentWidth: availableWidth
            ColumnLayout { width: parent.width; spacing: 10
                Note { visible: root.service.errorMessage.length > 0; text: root.service.errorMessage; color: Theme.red }
                RowLayout { Layout.fillWidth: true; Caption { text: "实例名称" } TextField { id: instanceName; Layout.fillWidth: true; font.pixelSize: 11 } CheckBox { id: instanceEnabled; visible: instanceDialog.editing; text: "允许新签发"; checked: true } }
                ColumnLayout {
                    Layout.fillWidth: true; visible: !instanceDialog.editing; spacing: 6
                    Note { text: "这里上传的是 CA 签名私钥，服务器会保存它。生产建议使用专用中间 CA；这与业务叶私钥留在本地及通信 mTLS 私钥仅本机会话使用的流程不同。"; color: Theme.red }
                    RowLayout { Layout.fillWidth: true; TextField { id: caCertificate; Layout.fillWidth: true; readOnly: true; placeholderText: "签发 CA PEM（≤64 KiB）"; font.pixelSize: 11 } Action { text: "CA 证书…"; onClicked: { filePicker.targetInput = caCertificate; filePicker.nameFilters = ["PEM CA (*.pem *.crt)"]; filePicker.open() } } }
                    RowLayout { Layout.fillWidth: true; TextField { id: caPrivateKey; Layout.fillWidth: true; readOnly: true; placeholderText: "配对的未加密 CA PEM 私钥（≤32 KiB）"; font.pixelSize: 11 } Action { text: "CA 私钥…"; onClicked: { filePicker.targetInput = caPrivateKey; filePicker.nameFilters = ["PEM 私钥 (*.pem *.key)"]; filePicker.open() } } }
                    RowLayout { Layout.fillWidth: true; TextField { id: caChain; Layout.fillWidth: true; readOnly: true; placeholderText: "上级链至自签名根；自签名 CA 可留空"; font.pixelSize: 11 } Action { text: "上级链…"; onClicked: { filePicker.targetInput = caChain; filePicker.nameFilters = ["PEM 链 (*.pem *.crt)"]; filePicker.open() } } }
                    CheckBox { id: uploadConfirmation; text: "我确认将此 CA 私钥上传并由所选管理端服务器保存"; font.pixelSize: 11 }
                }
                SigningPolicyEditor { id: instancePolicy; Layout.fillWidth: true }
                Note { text: instanceDialog.editing ? "将完整替换策略，并显式发送启用状态。不会修改已有证书，也不能就地更换 CA 材料。" : "创建没有可恢复的幂等缓存。若响应丢失，先刷新实例列表核对，不要盲目重复导入。"; color: Theme.amber; font.pixelSize: 10 }
            }
        }
        footer: DialogButtonBox {
            Action { text: "取消"; onClicked: instanceDialog.close() }
            Action { text: instanceDialog.editing ? "保存完整策略" : "上传 CA 并创建"; primary: true; enabled: !root.service.busy && (instanceDialog.editing || uploadConfirmation.checked); onClicked: {
                root.service.ownerSaveInstance({id: instanceDialog.editing ? root.service.ownerInstanceId : "", name: instanceName.text, enabled: instanceEnabled.checked,
                    certificateFile: caCertificate.text, privateKeyFile: caPrivateKey.text, chainFile: caChain.text, policy: instancePolicy.value()}, uploadConfirmation.checked)
                if (root.service.busy) instanceDialog.close()
            } }
        }
    }
    Dialog {
        id: credentialDialog; objectName: "credentialDialog"; anchors.centerIn: parent; width: Math.min(780, root.width - 20); height: Math.min(700, root.height - 20); modal: true; title: "创建实例专属签发 Token"
        onOpened: { credentialName.clear(); tokenLifetime.value = 720; tokenTotal.value = 1000; tokenRate.value = 10; restrictPolicy.checked = false; credentialPolicy.load({}); credentialIssue.checked = true; credentialRead.checked = true; credentialRevoke.checked = true }
        contentItem: ScrollView { clip: true; contentWidth: availableWidth
            ColumnLayout { width: parent.width; spacing: 10
                Note { visible: root.service.errorMessage.length > 0; text: root.service.errorMessage; color: Theme.red }
                TextField { id: credentialName; Layout.fillWidth: true; placeholderText: "凭据名称"; font.pixelSize: 11 }
                RowLayout { CheckBox { id: credentialIssue; text: "issue"; checked: true } CheckBox { id: credentialRead; text: "read"; checked: true } CheckBox { id: credentialRevoke; text: "revoke"; checked: true } }
                GridLayout {
                    columns: 2; columnSpacing: 10
                    Caption { text: "有效期 / 小时（1～2160，即 90 天）" } SpinBox { id: tokenLifetime; from: 1; to: 2160; value: 720; editable: true }
                    Caption { text: "累计签发额度" } SpinBox { id: tokenTotal; from: 1; to: 1000000; value: 1000; editable: true }
                    Caption { text: "每分钟成功签发上限" } SpinBox { id: tokenRate; from: 1; to: 120; value: 10; editable: true }
                }
                CheckBox { id: restrictPolicy; text: "为此 Token 添加额外完整策略（与实例策略取交集）"; font.pixelSize: 11 }
                SigningPolicyEditor { id: credentialPolicy; Layout.fillWidth: true; visible: restrictPolicy.checked }
                Note { text: "Token 明文只展示一次，关闭后无法从服务端找回。请通过安全渠道交付或导入签发连接。创建响应丢失时先核对凭据列表。"; color: Theme.amber }
            }
        }
        footer: DialogButtonBox {
            Action { text: "取消"; onClicked: credentialDialog.close() }
            Action { text: "创建并显示一次"; primary: true; enabled: !root.service.busy; onClicked: {
                var scopes = []; if (credentialIssue.checked) scopes.push("issue"); if (credentialRead.checked) scopes.push("read"); if (credentialRevoke.checked) scopes.push("revoke")
                root.service.ownerCreateCredential({name: credentialName.text, scopes: scopes, lifetimeSeconds: tokenLifetime.value * 3600, maxIssuances: tokenTotal.value, ratePerMinute: tokenRate.value, restrictPolicy: restrictPolicy.checked, policy: credentialPolicy.value()})
                if (root.service.busy) credentialDialog.close()
            } }
        }
    }
    Dialog {
        id: tokenDialog
        objectName: "tokenDialog"
        property string secret: ""
        anchors.centerIn: parent; width: Math.min(640, root.width - 20); modal: true; title: "新 Token · 仅显示这一次"
        standardButtons: Dialog.Close
        onOpened: standardButton(Dialog.Close).text = "关闭"
        onClosed: { secret = ""; revealToken.checked = false; allowCopy.checked = false }
        contentItem: ColumnLayout {
            Note { text: "关闭后无法恢复此 Token 明文。请妥善保存或导入签发连接；Token 本身不包含通信 mTLS 身份。"; color: Theme.amber }
            TextField { Layout.fillWidth: true; text: tokenDialog.secret; readOnly: true; selectByMouse: revealToken.checked; echoMode: revealToken.checked ? TextInput.Normal : TextInput.Password; font.pixelSize: 11 }
            CheckBox { id: revealToken; text: "显示一次性 Token" }
            RowLayout { CheckBox { id: allowCopy; text: "允许复制到系统剪贴板" } Action { text: "复制 Token"; enabled: allowCopy.checked; onClicked: App.copyToClipboard(tokenDialog.secret, "新签发 Token") } }
        }
    }
    FileDialog { id: filePicker; property var targetInput; onAccepted: if (targetInput) targetInput.text = selectedFile.toString() }
    FileDialog {
        id: exportDialog
        property bool artifact: false
        property string part: ""
        property string operationId: ""
        title: "导出公开证书文件"; fileMode: FileDialog.SaveFile
        onAccepted: {
            if (artifact) root.service.exportArtifact(part, selectedFile)
            else root.service.exportOperation(operationId, part, selectedFile)
        }
    }
    Connections {
        target: App
        function onVaultStateChanged() { if (!App.unlocked) root.clearSensitiveForms() }
    }
    Connections {
        target: root.service
        function onCredentialCreated(token) { tokenDialog.secret = token; tokenDialog.open() }
        function onChanged() {
            if (!App.unlocked) root.clearSensitiveForms()
        }
    }
}

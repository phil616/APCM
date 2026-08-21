import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CertManager

// qmllint disable unqualified

Rectangle {
    color: Theme.ink
    Component.onCompleted: password.forceActiveFocus()

    Rectangle {
        width: 460
        height: 294
        anchors.centerIn: parent
        color: Theme.panel
        border.width: 1
        border.color: Theme.lineBright
        radius: 2

        ColumnLayout {
            anchors.fill: parent
            spacing: 0

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 54
                color: "#F7F7F7"
                border.width: 1
                border.color: Theme.line
                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 16
                    anchors.rightMargin: 16
                    spacing: 12
                    Image {
                        Layout.preferredWidth: 30
                        Layout.preferredHeight: 30
                        source: "qrc:/icon.png"
                        fillMode: Image.PreserveAspectFit
                        smooth: true
                        mipmap: true
                    }
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 0
                        Text { text: "APCM"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 14; font.bold: true }
                        Text { text: "AltasCI multi-Platform Certificate Manager"; color: Theme.textDim; font.family: Theme.uiFont; font.pixelSize: 10 }
                    }
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.leftMargin: 24
                Layout.rightMargin: 24
                Layout.topMargin: 18
                Layout.bottomMargin: 18
                spacing: 8
                Text { text: App.vaultExists ? "解锁 APCM" : "初始化 APCM"; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 16; font.bold: true }
                Text { text: "主密码"; color: Theme.textMuted; font.family: Theme.uiFont; font.pixelSize: 11 }
                TextField {
                    id: password
                    Layout.fillWidth: true
                    Layout.preferredHeight: 32
                    echoMode: TextInput.Password
                    passwordCharacter: "●"
                    placeholderText: "至少 10 个字符"
                    color: Theme.text
                    placeholderTextColor: Theme.textDim
                    font.family: Theme.uiFont
                    selectByMouse: true
                    leftPadding: 8
                    background: Rectangle { color: Theme.panel; border.width: 1; border.color: password.activeFocus ? Theme.mint : Theme.lineBright; radius: 1 }
                    onAccepted: actionButton.clicked()
                }
                Text { visible: App.errorMessage.length > 0; Layout.fillWidth: true; text: App.errorMessage; color: Theme.red; wrapMode: Text.WordWrap; font.family: Theme.uiFont; font.pixelSize: 10 }
                Item { Layout.fillHeight: true }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: 8
                    Item { Layout.fillWidth: true }
                    Button {
                        id: exitButton
                        Layout.preferredWidth: 82
                        Layout.preferredHeight: 30
                        text: "退出"
                        contentItem: Text { text: exitButton.text; color: Theme.text; font.family: Theme.uiFont; font.pixelSize: 11; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter }
                        background: Rectangle { color: exitButton.hovered ? "#E5E5E5" : "#F5F5F5"; border.width: 1; border.color: Theme.lineBright; radius: 1 }
                        onClicked: App.exitApplication()
                    }
                    Button {
                        id: actionButton
                        Layout.preferredWidth: 112
                        Layout.preferredHeight: 30
                        text: App.vaultExists ? "解锁" : "初始化"
                        enabled: password.text.length >= 10 && !App.busy
                        contentItem: Text { text: actionButton.text; color: actionButton.enabled ? "white" : "#777777"; font.family: Theme.uiFont; font.pixelSize: 11; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter }
                        background: Rectangle { color: actionButton.enabled ? (actionButton.hovered ? "#005A9E" : Theme.mint) : "#D8D8D8"; border.width: 1; border.color: actionButton.enabled ? "#005A9E" : "#BFBFBF"; radius: 1 }
                        onClicked: {
                            App.clearMessage()
                            var ok = App.vaultExists ? App.unlockVault(password.text) : App.initializeVault(password.text)
                            if (ok) password.clear()
                        }
                    }
                }
            }
        }
    }
}

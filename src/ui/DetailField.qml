import QtQuick
import QtQuick.Layouts
import CertManager

ColumnLayout {
    id: root
    required property string label
    required property string value
    property bool mono: false
    spacing: 5
    Text { text: root.label; color: Theme.textDim; font.family: Theme.uiFont; font.pixelSize: 9; font.weight: Font.Bold; font.letterSpacing: 0.8 }
    Text { Layout.fillWidth: true; text: root.value; color: Theme.textMuted; wrapMode: Text.WrapAnywhere; font.family: Theme.uiFont; font.pixelSize: root.mono ? 10 : 12; lineHeight: 1.3 }
}

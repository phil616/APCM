import QtQuick
import CertManager

Item {
    id: root
    required property string title
    property string subtitle: ""
    implicitHeight: subtitle.length ? 48 : 28
    Text {
        text: root.title
        color: Theme.text
        font.family: Theme.uiFont
        font.pixelSize: 19
        font.weight: Font.DemiBold
    }
    Text {
        visible: root.subtitle.length > 0
        y: 27
        text: root.subtitle
        color: Theme.textMuted
        font.family: Theme.uiFont
        font.pixelSize: 11
    }
}

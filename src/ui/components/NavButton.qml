import QtQuick
import QtQuick.Controls
import CertManager

Button {
    id: root
    required property var modelData
    required property int index
    required property string label
    required property string mark
    property bool current: false
    implicitHeight: 34
    leftPadding: 8
    rightPadding: 8

    contentItem: Row {
        spacing: 8
        Text {
            width: 20
            anchors.verticalCenter: parent.verticalCenter
            text: root.mark
            color: root.current ? Theme.mint : Theme.textDim
            font.family: Theme.uiFont
            font.pixelSize: 10
            font.weight: Font.DemiBold
            horizontalAlignment: Text.AlignHCenter
        }
        Text {
            anchors.verticalCenter: parent.verticalCenter
            text: root.label
            color: root.current ? Theme.text : Theme.textMuted
            font.family: Theme.uiFont
            font.pixelSize: 12
            font.weight: root.current ? Font.DemiBold : Font.Normal
        }
    }
    background: Rectangle {
        radius: 2
        color: root.current ? "#DCEAF7" : (root.hovered ? "#E8E8E8" : "transparent")
        border.width: 0
        Rectangle {
            visible: root.current
            width: 3
            height: parent.height
            radius: 0
            color: Theme.mint
            anchors.left: parent.left
            anchors.leftMargin: 0
            anchors.verticalCenter: parent.verticalCenter
        }
        Behavior on color { ColorAnimation { duration: 120 } }
    }
}

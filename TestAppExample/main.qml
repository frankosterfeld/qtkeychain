import QtQuick 2.13
import QtQuick.Window 2.13
import QtQuick.Controls 2.12

Window {
    id: root

    width: 640
    height: 480
    visible: true

    Column {
        anchors {
            fill: parent
            margins: 50
        }
        spacing: 20

        Label {
            text: 'Key name:'
            font.pixelSize: 20
        }

        TextField {
            id: keyNameTextField

            width: parent.width
            height: 50

            text: 'default key name'
        }

        Label {
            text: 'Key value:'
            font.pixelSize: 20
        }

        TextField {
            id: keyValueTextField

            width: parent.width
            height: 50

            text: 'some value'
        }

        Label {
            id: infoLabel

            width: parent.width
            wrapMode: Text.Wrap
            visible: false

            onVisibleChanged: if (visible) hideAnimation.start();

            SequentialAnimation {
                id: hideAnimation

                PauseAnimation {
                    duration: 10000
                }

                ScriptAction {
                    script: infoLabel.visible = false
                }
            }

            Component.onCompleted: {
                KeyChain.keyStored.connect((key) => {
                                               infoLabel.text = String("Key '%1' successfully stored").arg(key)
                                               infoLabel.color = 'green'
                                               infoLabel.visible = true
                                           })

                KeyChain.keyRestored.connect((key, value) => {
                                               infoLabel.text = String("Key '%1' successfully restored with data '%2'").arg(key).arg(value)
                                               infoLabel.color = 'green'
                                               infoLabel.visible = true
                                           })

                KeyChain.keyDeleted.connect((key) => {
                                               infoLabel.text = String("Key '%1' successfully deleted").arg(key)
                                               infoLabel.color = 'green'
                                               infoLabel.visible = true
                                           })

                KeyChain.error.connect((errorText) => {
                                               infoLabel.text = errorText
                                               infoLabel.color = 'red'
                                               infoLabel.visible = true
                                           })
            }
        }

        Row {
            width: parent.width
            height: 50
            spacing: 20

            Button {
                width: 80
                height: parent.height
                text: 'Store'

                onClicked: {
                    KeyChain.writeKey(keyNameTextField.text.trim(), keyValueTextField.text.trim())
                }
            }

            Button {
                width: 80
                height: parent.height
                text: 'Restore'

                onClicked: {
                    KeyChain.readKey(keyNameTextField.text.trim())
                }
            }

            Button {
                width: 80
                height: parent.height
                text: 'Delete'
                onClicked: {
                    KeyChain.deleteKey(keyNameTextField.text.trim())
                }
            }
        }

    }
}

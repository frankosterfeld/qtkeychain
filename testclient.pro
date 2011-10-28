TEMPLATE = app
TARGET = testclient

SOURCES += testclient.cpp

QT -= gui
CONFIG += console
macx:CONFIG -= app_bundle

win32:LIBS += -Llib -lqtkeychain
unix:LIBS += -L$$OUT_PWD -lqtkeychain


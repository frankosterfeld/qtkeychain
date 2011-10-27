TEMPLATE = app
TARGET = testclient

SOURCES += testclient.cpp

QT -= gui
CONFIG += console
macx:CONFIG -= app_bundle

LIBS += -L$$OUT_PWD -lqtkeychain


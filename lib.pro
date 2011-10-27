TEMPLATE = lib
TARGET = qtkeychain
DEPENDPATH += .
INCLUDEPATH += .

# Input
HEADERS += keychain.h \
    keychain_p.h
SOURCES += keychain.cpp

macx {
    LIBS += -framework Security -framework CoreFoundation
    SOURCES += keychain_mac.cpp
}
win32:SOURCES += keychain_win.cpp


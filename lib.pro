TEMPLATE = lib
TARGET = qtkeychain
DEPENDPATH += .
INCLUDEPATH += .

HEADERS += keychain.h \
           keychain_p.h
SOURCES += keychain.cpp

DEFINES += QKEYCHAIN_BUILD_QKEYCHAIN_LIB

macx {
    LIBS += -framework Security -framework CoreFoundation
    SOURCES += keychain_mac.cpp
}
win32 {
    DESTDIR = lib
    DLLDESTDIR = lib
    SOURCES += keychain_win.cpp
}

cmake_minimum_required(VERSION 2.8)

project(qtkeychain)

find_package(Qt4 COMPONENTS QtCore REQUIRED)
include_directories(${QT_INCLUDES})

set(qtkeychain_SOURCES
    keychain.cpp
)

if(WIN32)
    list(APPEND qtkeychain_SOURCES keychain_win.cpp)
endif()

if(APPLE)
    list(APPEND qtkeychain_SOURCES keychain_mac.cpp)
endif()

if(UNIX AND NOT APPLE)
    list(APPEND qtkeychain_SOURCES keychain_dbus.cpp)
endif()

if(NOT QTKEYCHAIN_STATIC)
    add_library(qtkeychain SHARED ${qtkeychain_SOURCES})
    set_target_properties(qtkeychain PROPERTIES COMPILE_DEFINITIONS QKEYCHAIN_BUILD_QKEYCHAIN_LIB)
    target_link_libraries(qtkeychain ${QT_QTCORE_LIBRARY})
    if(WIN32)
        target_link_libraries(qtkeychain crypt32)
    endif()
else()
    add_library(qtkeychain STATIC ${qtkeychain_SOURCES})
endif()
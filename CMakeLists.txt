cmake_minimum_required(VERSION 2.8)
project(qtkeychain)

###

set(QTKEYCHAIN_VERSION 0.1.0)
set(QTKEYCHAIN_SOVERSION 0)

###

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" "${PROJECT_SOURCE_DIR}/cmake/Modules")
include(GNUInstallDirs)

# try Qt5 first, and prefer that if found
find_package(Qt5Core QUIET)
if (Qt5Core_FOUND)
  if(UNIX AND NOT APPLE)
    find_package(Qt5DBus REQUIRED)
    include_directories(${Qt5DBus_INCLUDE_DIRS})
    set(QTDBUS_LIBRARIES ${Qt5DBus_LIBRARIES})
    macro(qt_add_dbus_interface)
      qt5_add_dbus_interface(${ARGN})
    endmacro()
  endif()
  macro(qt_wrap_cpp)
    qt5_wrap_cpp(${ARGN})
  endmacro()

  set(QTCORE_LIBRARIES ${Qt5Core_LIBRARIES})
  include_directories(${Qt5Core_INCLUDE_DIRS})

  if (Qt5_POSITION_INDEPENDENT_CODE)
    if (CMAKE_VERSION VERSION_LESS 2.8.9) # TODO remove once we increase the cmake requirement
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
    else()
      set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    endif()
  endif()
else()
  if(UNIX AND NOT APPLE)
    find_package(Qt4 COMPONENTS QtCore QtDBus REQUIRED)
    macro(qt_add_dbus_interface)
      qt4_add_dbus_interface(${ARGN})
    endmacro()
    macro(qt_wrap_cpp)
      qt4_wrap_cpp(${ARGN})
    endmacro()
    set(QTDBUS_LIBRARIES ${QT_QTDBUS_LIBRARY})
  else()
    find_package(Qt4 COMPONENTS QtCore REQUIRED)
  endif()
  include_directories(${QT_INCLUDES})
  set(QTCORE_LIBRARIES ${QT_QTCORE_LIBRARY})
endif()


include_directories(${CMAKE_CURRENT_BINARY_DIR})

list(APPEND qtkeychain_LIBRARIES ${QTCORE_LIBRARIES})
set(qtkeychain_SOURCES
    keychain.cpp
)


if(WIN32)
    list(APPEND qtkeychain_SOURCES keychain_win.cpp)
    list(APPEND qtkeychain_LIBRARIES crypt32)
    #FIXME: mingw bug; otherwise getting undefined refs to RtlSecureZeroMemory there
    if(MINGW)
        add_definitions( -O2 )
    endif()
endif()

if(APPLE)
    list(APPEND qtkeychain_SOURCES keychain_mac.cpp)

    find_library(COREFOUNDATION_LIBRARY CoreFoundation)
    list(APPEND qtkeychain_LIBRARIES ${COREFOUNDATION_LIBRARY})

    find_library(SECURITY_LIBRARY Security)
    list(APPEND qtkeychain_LIBRARIES ${SECURITY_LIBRARY})
endif()

if(UNIX AND NOT APPLE)
    list(APPEND qtkeychain_SOURCES keychain_dbus.cpp)
    qt_add_dbus_interface(qtkeychain_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/org.kde.KWallet.xml kwallet_interface KWalletInterface)
    list(APPEND qtkeychain_LIBRARIES ${QTDBUS_LIBRARIES})
endif()

QT_WRAP_CPP(qtkeychain_MOC_OUTFILES keychain.h keychain_p.h)

if(NOT QTKEYCHAIN_STATIC)
    add_library(qtkeychain SHARED ${qtkeychain_SOURCES} ${qtkeychain_MOC_OUTFILES})
    set_target_properties(qtkeychain PROPERTIES COMPILE_DEFINITIONS QKEYCHAIN_BUILD_QKEYCHAIN_LIB)
    target_link_libraries(qtkeychain ${qtkeychain_LIBRARIES})
else()
    add_library(qtkeychain STATIC ${qtkeychain_SOURCES} ${qtkeychain_MOC_OUTFILES})
    set_target_properties(qtkeychain PROPERTIES COMPILE_DEFINITIONS QKEYCHAIN_STATICLIB)
endif()

set_target_properties(qtkeychain PROPERTIES
    VERSION ${QTKEYCHAIN_VERSION}
    SOVERSION ${QTKEYCHAIN_SOVERSION}
)

install(FILES keychain.h qkeychain_export.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qtkeychain/
)

install(TARGETS qtkeychain
  EXPORT QtKeychainLibraryDepends
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_executable( testclient testclient.cpp )
target_link_libraries( testclient qtkeychain)


###
### CMake config file
###

export(TARGETS qtkeychain FILE "${PROJECT_BINARY_DIR}/QtKeychainLibraryDepends.cmake")
export(PACKAGE QtKeychain)

configure_file(QtKeychainBuildTreeSettings.cmake.in
  "${PROJECT_BINARY_DIR}/QtKeychainBuildTreeSettings.cmake" @ONLY)
configure_file(QtKeychainConfig.cmake.in
  "${PROJECT_BINARY_DIR}/QtKeychainConfig.cmake" @ONLY)
configure_file(QtKeychainConfigVersion.cmake.in
  "${PROJECT_BINARY_DIR}/QtKeychainConfigVersion.cmake" @ONLY)

install(EXPORT QtKeychainLibraryDepends
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/QtKeychain"
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/QtKeychainConfig.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/QtKeychainConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/QtKeychain
)


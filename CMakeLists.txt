cmake_minimum_required(VERSION 2.8)
project(qtkeychain)

###

set(QTKEYCHAIN_VERSION 0.4.90)
set(QTKEYCHAIN_SOVERSION 0)

###

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" "${PROJECT_SOURCE_DIR}/cmake/Modules")
include(GNUInstallDirs)

option(BUILD_WITH_QT4 "Build qtkeychain with Qt4 no matter if Qt5 was found" OFF)


if( NOT BUILD_WITH_QT4 )
    # try Qt5 first, and prefer that if found
    find_package(Qt5Core QUIET)
endif()

if (Qt5Core_FOUND)
  set(QTKEYCHAIN_VERSION_INFIX 5)
  if(UNIX AND NOT APPLE)
    find_package(Qt5DBus REQUIRED)
    include_directories(${Qt5DBus_INCLUDE_DIRS})
    set(QTDBUS_LIBRARIES ${Qt5DBus_LIBRARIES})
    macro(qt_add_dbus_interface)
      qt5_add_dbus_interface(${ARGN})
    endmacro()
  endif()
  find_package(Qt5LinguistTools REQUIRED)
  macro(qt_add_translation)
    qt5_add_translation(${ARGN})
  endmacro(qt_add_translation)
  macro(qt_create_translation)
    qt5_create_translation(${ARGN})
  endmacro(qt_create_translation)
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
  set(QTKEYCHAIN_VERSION_INFIX "")
  if(UNIX AND NOT APPLE)
    find_package(Qt4 COMPONENTS QtCore QtDBus REQUIRED)
    set(QTDBUS_LIBRARIES ${QT_QTDBUS_LIBRARY})
    macro(qt_add_dbus_interface)
      qt4_add_dbus_interface(${ARGN})
    endmacro()
  else()
    find_package(Qt4 COMPONENTS QtCore REQUIRED)
  endif()
  include_directories(${QT_INCLUDES})
  set(QTCORE_LIBRARIES ${QT_QTCORE_LIBRARY})
  macro(qt_add_translation)
    qt4_add_translation(${ARGN})
  endmacro(qt_add_translation)
  macro(qt_create_translation)
    qt4_create_translation(${ARGN})
  endmacro(qt_create_translation)
  macro(qt_wrap_cpp)
    qt4_wrap_cpp(${ARGN})
  endmacro()
endif()


include_directories(${CMAKE_CURRENT_BINARY_DIR})

list(APPEND qtkeychain_LIBRARIES ${QTCORE_LIBRARIES})
set(qtkeychain_SOURCES
    keychain.cpp
)

ADD_DEFINITIONS( -Wall )

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
    list(APPEND qtkeychain_SOURCES keychain_unix.cpp gnomekeyring.cpp)
    qt_add_dbus_interface(qtkeychain_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/org.kde.KWallet.xml kwallet_interface KWalletInterface)
    list(APPEND qtkeychain_LIBRARIES ${QTDBUS_LIBRARIES})
endif()

QT_WRAP_CPP(qtkeychain_MOC_OUTFILES keychain.h keychain_p.h)

set(qtkeychain_TR_FILES
      translations/qtkeychain_de.ts
      translations/qtkeychain_ro.ts
)

file(GLOB qtkeychain_TR_SOURCES *.cpp *.h *.ui)
qt_create_translation(qtkeychain_MESSAGES ${qtkeychain_TR_SOURCES} ${qtkeychain_TR_FILES})
qt_add_translation(qtkeychain_QM_FILES ${qtkeychain_TR_FILES})
add_custom_target(messages DEPENDS ${qtkeychain_MESSAGES})
add_custom_target(translations DEPENDS ${qtkeychain_QM_FILES})

if(NOT QT_TRANSLATIONS_DIR)
    # If this directory is missing, we are in a Qt5 environment.
    # Extract the qmake executable location
    get_target_property(QT5_QMAKE_EXECUTABLE Qt5::qmake IMPORTED_LOCATION)
    # Ask Qt5 where to put the translations
    EXEC_PROGRAM( ${QT5_QMAKE_EXECUTABLE}
        ARGS -query QT_INSTALL_TRANSLATIONS
        OUTPUT_VARIABLE qt_translations_dir )
    # make sure we have / and not \ as qmake gives on windows
    FILE(TO_CMAKE_PATH "${qt_translations_dir}" qt_translations_dir)
    SET(QT_TRANSLATIONS_DIR ${qt_translations_dir} CACHE PATH "The
    location of the Qt translations" FORCE)
endif()

install(FILES ${qtkeychain_QM_FILES}
        DESTINATION ${QT_TRANSLATIONS_DIR})

set(QTKEYCHAIN_TARGET_NAME qt${QTKEYCHAIN_VERSION_INFIX}keychain)
if(NOT QTKEYCHAIN_STATIC)
    add_library(${QTKEYCHAIN_TARGET_NAME} SHARED ${qtkeychain_SOURCES} ${qtkeychain_MOC_OUTFILES} ${qtkeychain_QM_FILES})
    set_target_properties(${QTKEYCHAIN_TARGET_NAME} PROPERTIES COMPILE_DEFINITIONS QKEYCHAIN_BUILD_QKEYCHAIN_LIB)
    target_link_libraries(${QTKEYCHAIN_TARGET_NAME} ${qtkeychain_LIBRARIES})
else()
    add_library(${QTKEYCHAIN_TARGET_NAME} STATIC ${qtkeychain_SOURCES} ${qtkeychain_MOC_OUTFILES} ${qtkeychain_QM_FILES})
    set_target_properties(${QTKEYCHAIN_TARGET_NAME} PROPERTIES COMPILE_DEFINITIONS QKEYCHAIN_STATICLIB)
endif()

set_target_properties(${QTKEYCHAIN_TARGET_NAME} PROPERTIES
    VERSION ${QTKEYCHAIN_VERSION}
    SOVERSION ${QTKEYCHAIN_SOVERSION}
    MACOSX_RPATH 1
    INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}"
)

install(FILES keychain.h qkeychain_export.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qt${QTKEYCHAIN_VERSION_INFIX}keychain/
)

install(TARGETS ${QTKEYCHAIN_TARGET_NAME}
  EXPORT Qt${QTKEYCHAIN_VERSION_INFIX}KeychainLibraryDepends
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_executable( testclient testclient.cpp )
target_link_libraries( testclient ${QTKEYCHAIN_TARGET_NAME})


###
### CMake config file
###

export(TARGETS ${QTKEYCHAIN_TARGET_NAME} FILE "${PROJECT_BINARY_DIR}/Qt${QTKEYCHAIN_VERSION_INFIX}KeychainLibraryDepends.cmake")
export(PACKAGE Qt${QTKEYCHAIN_VERSION_INFIX}Keychain)

configure_file(QtKeychainBuildTreeSettings.cmake.in
  "${PROJECT_BINARY_DIR}/Qt${QTKEYCHAIN_VERSION_INFIX}KeychainBuildTreeSettings.cmake" @ONLY)
configure_file(QtKeychainConfig.cmake.in
  "${PROJECT_BINARY_DIR}/Qt${QTKEYCHAIN_VERSION_INFIX}KeychainConfig.cmake" @ONLY)
configure_file(QtKeychainConfigVersion.cmake.in
  "${PROJECT_BINARY_DIR}/Qt${QTKEYCHAIN_VERSION_INFIX}KeychainConfigVersion.cmake" @ONLY)

install(EXPORT Qt${QTKEYCHAIN_VERSION_INFIX}KeychainLibraryDepends
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/Qt${QTKEYCHAIN_VERSION_INFIX}Keychain"
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/Qt${QTKEYCHAIN_VERSION_INFIX}KeychainConfig.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/Qt${QTKEYCHAIN_VERSION_INFIX}KeychainConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Qt${QTKEYCHAIN_VERSION_INFIX}Keychain
)


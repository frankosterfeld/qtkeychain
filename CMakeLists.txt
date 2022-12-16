cmake_minimum_required(VERSION 3.16)

set(QTKEYCHAIN_VERSION 0.13.99)
set(QTKEYCHAIN_SOVERSION 1)

project(qtkeychain VERSION ${QTKEYCHAIN_VERSION} LANGUAGES CXX)

# Enable C++11
SET(CMAKE_CXX_STANDARD 11)

include(FindPkgConfig)

###

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" "${PROJECT_SOURCE_DIR}/cmake/Modules")
include(GNUInstallDirs)
include(GenerateExportHeader)
include(CMakePackageConfigHelpers)
include(ECMSetupVersion)
include(ECMGeneratePriFile)
include(CMakeDependentOption)

option(BUILD_WITH_QT6 "Build qtkeychain with Qt 6" OFF)
option(BUILD_TEST_APPLICATION "Build test application" OFF)
option(BUILD_TRANSLATIONS "Build translations" ON)
option(BUILD_SHARED_LIBS "Build dynamic library" ON)
option(QTKEYCHAIN_TARGET_NAME "Custom output name of QtKeychain" "")
if(QTKEYCHAIN_STATIC)
    set(BUILD_SHARED_LIBS OFF)
    message(WARNING "QTKEYCHAIN_STATIC is deprecated. Use BUILD_SHARED_LIBS=OFF instead.")
endif()
CMAKE_DEPENDENT_OPTION(BUILD_TRANSLATIONS_AS_RESOURCES "Bundle translations with the library" OFF
                       "BUILD_TRANSLATIONS" OFF)

if(CMAKE_SYSTEM_NAME STREQUAL Android)
    set(ANDROID 1)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL Haiku)
    set(HAIKU 1)
endif()

if (WIN32)
    option(USE_CREDENTIAL_STORE "Build with windows CredentialStore support" ON)

    if (USE_CREDENTIAL_STORE)
        add_definitions(-DUSE_CREDENTIAL_STORE=1)
    endif()
endif()

if( NOT BUILD_WITH_QT6 )
    find_package(Qt5 COMPONENTS Core REQUIRED)
endif()

if (Qt5Core_FOUND AND NOT BUILD_WITH_QT6)
  set(QTKEYCHAIN_VERSION_INFIX 5)

  if(ANDROID)
    if(Qt5Core_VERSION VERSION_LESS 5.7)
        find_package(Qt5 COMPONENTS Core REQUIRED Private)
        include_directories(${Qt5Core_PRIVATE_INCLUDE_DIRS})
    endif()

    find_package(Qt5 COMPONENTS AndroidExtras REQUIRED)
    include_directories(${Qt5AndroidExtras_INCLUDE_DIRS})
    set(QTANDROIDEXTRAS_LIBRARIES ${Qt5AndroidExtras_LIBRARIES})
  endif()

  if(UNIX AND NOT APPLE AND NOT ANDROID AND NOT HAIKU)
    find_package(Qt5 COMPONENTS DBus REQUIRED)
    include_directories(${Qt5DBus_INCLUDE_DIRS})
    set(QTDBUS_LIBRARIES ${Qt5DBus_LIBRARIES})
    macro(qt_add_dbus_interface)
      qt5_add_dbus_interface(${ARGN})
    endmacro()
  endif()

  if(BUILD_TRANSLATIONS)
    find_package(Qt5 COMPONENTS LinguistTools REQUIRED)
    macro(qt_add_translation)
      qt5_add_translation(${ARGN})
    endmacro(qt_add_translation)
    macro(qt_create_translation)
      qt5_create_translation(${ARGN})
    endmacro(qt_create_translation)
  endif()

  macro(qt_wrap_cpp)
    qt5_wrap_cpp(${ARGN})
  endmacro()

  set(QTCORE_LIBRARIES ${Qt5Core_LIBRARIES})
  include_directories(${Qt5Core_INCLUDE_DIRS})
else()
  find_package(Qt6 COMPONENTS Core REQUIRED)
  set(QTKEYCHAIN_VERSION_INFIX 6)


  if(UNIX AND NOT APPLE AND NOT ANDROID AND NOT HAIKU)
    find_package(Qt6 COMPONENTS DBus REQUIRED)
    include_directories(${Qt6DBus_INCLUDE_DIRS})
    set(QTDBUS_LIBRARIES ${Qt6DBus_LIBRARIES})
    macro(qt_add_dbus_interface)
      qt6_add_dbus_interface(${ARGN})
    endmacro()
  endif()

  if(BUILD_TRANSLATIONS)
    find_package(Qt6 COMPONENTS LinguistTools REQUIRED)
    macro(qt_add_translation)
      qt6_add_translation(${ARGN})
    endmacro(qt_add_translation)
    macro(qt_create_translation)
      qt6_create_translation(${ARGN})
    endmacro(qt_create_translation)
  endif()

  macro(qt_wrap_cpp)
    qt6_wrap_cpp(${ARGN})
  endmacro()

  set(QTCORE_LIBRARIES ${Qt6Core_LIBRARIES})
endif()


include_directories(${CMAKE_CURRENT_BINARY_DIR})

list(APPEND qtkeychain_LIBRARIES ${QTCORE_LIBRARIES})
set(qtkeychain_SOURCES
    keychain.cpp
    qkeychain_export.h
    keychain.h
)

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    # CMake < 3.15 sneaks in /W# flags for us, so we need a replacement,
    # or we'll get a warning (cf. CMP0092)
    if (CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
        string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    else()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
    endif()
else()
    # MSVC's STL / Qt headers are not MSVC -Wall clean, so don't enable it there
    add_definitions( -Wall -Werror=return-type )
endif()

if(WIN32)
    list(APPEND qtkeychain_SOURCES keychain_win.cpp)
    if (NOT USE_CREDENTIAL_STORE)
        list(APPEND qtkeychain_LIBRARIES crypt32)
        list(APPEND qtkeychain_SOURCES plaintextstore.cpp)
    endif()
    #FIXME: mingw bug; otherwise getting undefined refs to RtlSecureZeroMemory there
    if(MINGW)
        add_definitions( -O2 )
    endif()
endif()

if(APPLE)
    list(APPEND qtkeychain_SOURCES keychain_apple.mm)
    list(APPEND qtkeychain_LIBRARIES "-framework Foundation" "-framework Security")
endif()

if(HAIKU)
    list(APPEND qtkeychain_SOURCES keychain_haiku.cpp)

    find_library(BE_LIBRARY be REQUIRED)
    list(APPEND qtkeychain_LIBRARIES ${BE_LIBRARY})
endif()

if(UNIX AND NOT APPLE AND NOT ANDROID AND NOT HAIKU)
    option(LIBSECRET_SUPPORT "Build with libsecret support" ON)

    if(LIBSECRET_SUPPORT)
        pkg_check_modules(LIBSECRET REQUIRED libsecret-1)
        add_definitions(-DHAVE_LIBSECRET=1)
        INCLUDE_DIRECTORIES(${LIBSECRET_INCLUDE_DIRS})
        LINK_DIRECTORIES(${LIBSECRET_LIBRARY_DIRS})
        list(APPEND qtkeychain_LIBRARIES_PRIVATE ${LIBSECRET_LIBRARIES})
    endif()

    add_definitions(-DKEYCHAIN_DBUS=1)
    list(APPEND qtkeychain_SOURCES keychain_unix.cpp gnomekeyring.cpp libsecret.cpp plaintextstore.cpp)
    qt_add_dbus_interface(qtkeychain_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/org.kde.KWallet.xml kwallet_interface KWalletInterface)
    list(APPEND qtkeychain_LIBRARIES ${QTDBUS_LIBRARIES} )
endif()

if(ANDROID)
    list(APPEND qtkeychain_SOURCES keychain_android.cpp androidkeystore.cpp plaintextstore.cpp)
    list(APPEND qtkeychain_LIBRARIES_PRIVATE ${QTANDROIDEXTRAS_LIBRARIES} )
endif()

QT_WRAP_CPP(qtkeychain_MOC_OUTFILES keychain.h keychain_p.h gnomekeyring_p.h)

set(qtkeychain_TR_FILES
      translations/qtkeychain_de.ts
      translations/qtkeychain_fr.ts
      translations/qtkeychain_ro.ts
      translations/qtkeychain_ru.ts
      translations/qtkeychain_zh.ts
)
if(NOT QTKEYCHAIN_TARGET_NAME)
	set(QTKEYCHAIN_TARGET_NAME Qt${QTKEYCHAIN_VERSION_INFIX}Keychain)
endif()
add_library(${QTKEYCHAIN_TARGET_NAME} ${qtkeychain_SOURCES} ${qtkeychain_MOC_OUTFILES} ${qtkeychain_QM_FILES})
if(WIN32)
    set_target_properties( ${QTKEYCHAIN_TARGET_NAME} PROPERTIES DEBUG_POSTFIX "d" )
endif()

file(GLOB qtkeychain_TR_SOURCES *.cpp *.h *.ui)
if ( BUILD_TRANSLATIONS )
    qt_create_translation(qtkeychain_MESSAGES ${qtkeychain_TR_SOURCES} ${qtkeychain_TR_FILES})
    qt_add_translation(qtkeychain_QM_FILES ${qtkeychain_TR_FILES})
    add_custom_target(messages DEPENDS ${qtkeychain_MESSAGES})
    add_custom_target(translations DEPENDS ${qtkeychain_QM_FILES} messages)
    # https://github.com/frankosterfeld/qtkeychain/issues/185
    add_dependencies(${QTKEYCHAIN_TARGET_NAME} translations)

    if (BUILD_TRANSLATIONS_AS_RESOURCES)
        set(QM_FILE_LIST "")
        foreach(FILE ${qtkeychain_QM_FILES})
            list(APPEND QM_FILE_LIST "<file>${FILE}</file>")
        endforeach()
        string(REPLACE ";" "" QM_FILE_LIST ${QM_FILE_LIST})
        configure_file(${CMAKE_CURRENT_SOURCE_DIR}/translations/translations.qrc.in ${CMAKE_CURRENT_BINARY_DIR}/translations.qrc)
        target_sources(${QTKEYCHAIN_TARGET_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/translations.qrc)
    else()
        if(QTKEYCHAIN_VERSION_INFIX EQUAL 5 AND QT_TRANSLATIONS_DIR AND NOT QTKEYCHAIN_TRANSLATIONS_DIR)
            # Back compatibility with pre-0.11 versions
            message (WARNING "QT_TRANSLATIONS_DIR is deprecated, use QTKEYCHAIN_TRANSLATIONS_DIR instead")
            set(QTKEYCHAIN_TRANSLATIONS_DIR ${QT_TRANSLATIONS_DIR}
                CACHE PATH "The location of the QtKeychain translations" FORCE)
        else()
            set(QTKEYCHAIN_TRANSLATIONS_DIR
                ${CMAKE_INSTALL_DATADIR}/${QTKEYCHAIN_TARGET_NAME}/translations
                CACHE PATH "The location of the QtKeychain translations" )
        endif()

        install(FILES ${qtkeychain_QM_FILES} DESTINATION ${QTKEYCHAIN_TRANSLATIONS_DIR})
    endif()
endif( BUILD_TRANSLATIONS )

target_link_libraries(${QTKEYCHAIN_TARGET_NAME} PUBLIC ${qtkeychain_LIBRARIES} PRIVATE ${qtkeychain_LIBRARIES_PRIVATE})
if(NOT INTERFACE_INCLUDE_SUFFIX)
    set(INTERFACE_INCLUDE_SUFFIX include)
endif()
target_include_directories(${QTKEYCHAIN_TARGET_NAME} PUBLIC $<INSTALL_INTERFACE:${INTERFACE_INCLUDE_SUFFIX}/>)

generate_export_header(${QTKEYCHAIN_TARGET_NAME}
  EXPORT_FILE_NAME qkeychain_export.h
  EXPORT_MACRO_NAME QKEYCHAIN_EXPORT
)

set_target_properties(${QTKEYCHAIN_TARGET_NAME} PROPERTIES
    VERSION ${QTKEYCHAIN_VERSION}
    SOVERSION ${QTKEYCHAIN_SOVERSION}
    INSTALL_RPATH_USE_LINK_PATH TRUE
)

if (NOT APPLE)
	set_target_properties(${QTKEYCHAIN_TARGET_NAME} PROPERTIES
		INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}"
		)
endif()

install(FILES keychain.h ${CMAKE_CURRENT_BINARY_DIR}/qkeychain_export.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${QTKEYCHAIN_TARGET_NAME}/
)

install(TARGETS ${QTKEYCHAIN_TARGET_NAME}
  EXPORT ${QTKEYCHAIN_TARGET_NAME}LibraryDepends
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

if(BUILD_TEST_APPLICATION)
    add_executable( testclient testclient.cpp )
    target_link_libraries( testclient ${QTKEYCHAIN_TARGET_NAME})
endif()


###
### CMake config file
###

configure_package_config_file("${CMAKE_CURRENT_SOURCE_DIR}/QtKeychainConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/${QTKEYCHAIN_TARGET_NAME}Config.cmake"
  INSTALL_DESTINATION ${QTKEYCHAIN_TARGET_NAME})

ecm_setup_version("${QTKEYCHAIN_VERSION}" VARIABLE_PREFIX SNORE
  PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/${QTKEYCHAIN_TARGET_NAME}ConfigVersion.cmake"
  SOVERSION ${QTKEYCHAIN_VERSION})

if(UNIX AND NOT APPLE AND NOT ANDROID AND NOT HAIKU)
    set(PRI_EXTRA_DEPS "dbus")
endif()
ecm_generate_pri_file(BASE_NAME ${QTKEYCHAIN_TARGET_NAME}
  LIB_NAME ${QTKEYCHAIN_TARGET_NAME}
  DEPS "core ${PRI_EXTRA_DEPS}"
  INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}
  FILENAME_VAR pri_filename)

install(FILES ${pri_filename} DESTINATION ${ECM_MKSPECS_INSTALL_DIR})


install(EXPORT ${QTKEYCHAIN_TARGET_NAME}LibraryDepends
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${QTKEYCHAIN_TARGET_NAME}"
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${QTKEYCHAIN_TARGET_NAME}Config.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/${QTKEYCHAIN_TARGET_NAME}ConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${QTKEYCHAIN_TARGET_NAME}
)


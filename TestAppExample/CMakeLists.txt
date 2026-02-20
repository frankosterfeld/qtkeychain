cmake_minimum_required(VERSION 3.16)
project(TestAppExample VERSION ${QTKEYCHAIN_VERSION} LANGUAGES CXX)

include(GNUInstallDirs)

# Enable C++11
SET(CMAKE_CXX_STANDARD 11)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(BUNDLE_IDENTIFIER "org.qtkeychain.TestAppExample")

option(BUILD_WITH_QT6 "Build qtkeychain with Qt 6" OFF)
if (BUILD_WITH_QT6)
	set(QTx Qt6)
else()
	set(QTx Qt5)
endif()

find_package(${QTx}Keychain REQUIRED)
find_package(${QTx} COMPONENTS Core Network Quick Qml REQUIRED)

if (BUILD_WITH_QT6)
	include_directories(${QTKEYCHAIN_INCLUDE_DIRS}/qt6keychain)
else()
	include_directories(${QTKEYCHAIN_INCLUDE_DIRS}/qt5keychain)
endif()

qt_add_resources(QT_RESOURCES qml.qrc)

if(BUILD_WITH_QT6)
	qt_add_executable(${PROJECT_NAME}
		keychainclass.h
		keychainclass.cpp
		main.cpp
		${QT_RESOURCES}
	)
else()
	add_executable(${PROJECT_NAME}
		keychainclass.h
		keychainclass.cpp
		main.cpp
		${QT_RESOURCES}
	)
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
	MACOSX_BUNDLE_GUI_IDENTIFIER ${BUNDLE_IDENTIFIER}
	MACOSX_BUNDLE_IDENTIFIER ${BUNDLE_IDENTIFIER}
	MACOSX_BUNDLE_BUNDLE_NAME ${PROJECT_NAME}
	MACOSX_BUNDLE TRUE
)

target_link_libraries(${PROJECT_NAME} PRIVATE ${QTx}::Core ${QTx}::Network ${QTx}::Quick ${QTx}::Qml ${QTx}Keychain::${QTx}Keychain)

if(BUILD_WITH_QT6)
	qt_import_qml_plugins(${PROJECT_NAME})
endif()

install(TARGETS ${PROJECT_NAME}
	BUNDLE DESTINATION .
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

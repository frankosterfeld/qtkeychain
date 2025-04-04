include(ECMAddTests)

if (BUILD_WITH_QT6)
    find_package(Qt6 CONFIG COMPONENTS Test REQUIRED)
else()
    find_package(Qt5 CONFIG COMPONENTS Test REQUIRED)
endif()

ecm_add_tests(basic.cpp LINK_LIBRARIES ${QTKEYCHAIN_TARGET_NAME} Qt${QT_MAJOR_VERSION}::Test)
set_property(TARGET basic PROPERTY AUTOMOC ON)

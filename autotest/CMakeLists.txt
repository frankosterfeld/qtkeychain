include(ECMAddTests)

find_package(Qt${QT_MAJOR_VERSION} COMPONENTS Test REQUIRED)

ecm_add_tests(basic.cpp LINK_LIBRARIES ${QTKEYCHAIN_TARGET_NAME} Qt${QT_MAJOR_VERSION}::Test)
set_property(TARGET basic PROPERTY AUTOMOC ON)

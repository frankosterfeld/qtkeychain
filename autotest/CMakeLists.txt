include(ECMAddTests)

if (BUILD_WITH_QT6)
    find_package(Qt6 CONFIG COMPONENTS Core Test REQUIRED)
else()
    find_package(Qt5 CONFIG COMPONENTS Core Test REQUIRED)
endif()

ecm_add_tests(basic.cpp LINK_LIBRARIES ${QTKEYCHAIN_TARGET_NAME} Qt${QT_MAJOR_VERSION}::Test)
set_property(TARGET basic PROPERTY AUTOMOC ON)

if(EMSCRIPTEN)
    target_link_options(basic PRIVATE "-sASYNCIFY")
endif()

cmake_minimum_required(VERSION 3.24)

project(CertificateManager VERSION 0.1.2 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Qt6 6.8 REQUIRED COMPONENTS Core Gui Network Quick QuickControls2 Test)
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(sqlcipher CONFIG REQUIRED)
find_package(tl-expected CONFIG REQUIRED)

qt_standard_project_setup(REQUIRES 6.8)

add_library(certmgr_core STATIC
    src/domain/certificate/CertificateInfo.cpp
    src/domain/enrollment/EnrollmentRequest.cpp
    src/services/TemplateService.cpp
    src/services/PkiConsoleClient.cpp
    src/connectors/ManualCAConnector.cpp
    src/app/SingleInstanceGuard.cpp
    src/persistence/SecureBuffer.cpp
    src/persistence/SqlCipherVault.cpp
    src/platform/windows/common/WinError.cpp
    src/platform/windows/credentials/WindowsCredentialStore.cpp
    src/platform/windows/certificate_store/WindowsCertificateStore.cpp
    src/platform/windows/cng/WindowsCngKeyProvider.cpp
    src/platform/windows/cert_enroll/WindowsCertEnrollBackend.cpp
    src/platform/windows/privilege/ElevatedHelperLauncher.cpp
)

target_include_directories(certmgr_core PUBLIC src)
target_compile_definitions(certmgr_core PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(certmgr_core
    PUBLIC Qt6::Core Qt6::Network tl::expected
    PRIVATE
        unofficial-sodium::sodium
        sqlcipher::sqlcipher
        Crypt32 Ncrypt Bcrypt Ole32 OleAut32 Shell32 Advapi32
)

if(MSVC)
    target_compile_options(certmgr_core PRIVATE /W4 /permissive- /utf-8 /EHsc)
endif()

qt_add_executable(CertificateManager WIN32
    src/app/main.cpp
    src/app/AppController.cpp
    src/app/CertificateListModel.cpp
    resources/apcm.rc
)

qt_add_resources(CertificateManager app_resources
    PREFIX "/"
    FILES icon.png
)

set_source_files_properties(src/ui/Theme.qml PROPERTIES QT_QML_SINGLETON_TYPE TRUE)

qt_add_qml_module(CertificateManager
    URI CertManager
    VERSION 1.0
    QML_FILES
        src/ui/Main.qml
        src/ui/Theme.qml
        src/ui/UnlockPage.qml
        src/ui/DetailField.qml
        src/ui/components/NavButton.qml
        src/ui/components/SectionHeading.qml
)

target_link_libraries(CertificateManager PRIVATE
    certmgr_core
    Qt6::Gui
    Qt6::Quick
    Qt6::QuickControls2
    unofficial-sodium::sodium
)
target_compile_definitions(CertificateManager PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    CERTMGR_VERSION="${PROJECT_VERSION}"
)
if(MSVC)
    target_compile_options(CertificateManager PRIVATE /W4 /permissive- /utf-8 /EHsc)
endif()

qt_add_executable(CertificateManagerHelper WIN32
    src/helper/main.cpp
    resources/apcm.rc
)
set_target_properties(CertificateManagerHelper PROPERTIES OUTPUT_NAME "CertificateManager.Helper")
target_link_libraries(CertificateManagerHelper PRIVATE certmgr_core Qt6::Core)
target_compile_definitions(CertificateManagerHelper PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)

include(CTest)
if(BUILD_TESTING)
    qt_add_executable(certmgr_tests
        tests/TestCore.cpp
    )
    target_link_libraries(certmgr_tests PRIVATE certmgr_core Qt6::Test unofficial-sodium::sodium)
    add_test(NAME certmgr_core_tests COMMAND certmgr_tests)
    set_tests_properties(certmgr_core_tests PROPERTIES
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${Qt6_DIR}/../../../bin"
    )
endif()

install(TARGETS CertificateManager CertificateManagerHelper
    BUNDLE DESTINATION .
    RUNTIME DESTINATION bin
)

qt_generate_deploy_qml_app_script(
    TARGET CertificateManager
    OUTPUT_SCRIPT deploy_script
    DEPLOY_TOOL_OPTIONS
        --no-translations
        --no-compiler-runtime
        --skip-plugin-types qmltooling
    NO_UNSUPPORTED_PLATFORM_ERROR
)
install(SCRIPT ${deploy_script})

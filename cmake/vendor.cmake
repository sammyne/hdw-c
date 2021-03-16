
FetchContent_Declare(
  mbedtls
  #GIT_REPOSITORY        https://github.com/ARMmbed/mbedtls.git
  GIT_REPOSITORY        https://gitee.com/mirrors/mbedtls.git
  GIT_TAG               v2.25.0
  SOURCE_DIR            ${PROJECT_SOURCE_DIR}/vendor/mbedtls
  INSTALL_COMMAND       "skipping install for mbedtls"
  TEST_COMMAND          "skipping test for mbedtls"
)
#  INSTALL_DIR           ${PROJECT_BINARY_DIR}

FetchContent_MakeAvailable(mbedtls)

FetchContent_GetProperties(mbedtls
  BINARY_DIR mbedtlsBinDir
  SOURCE_DIR mbedtlsDir
)

# Install script for directory: /home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/mbedtls" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/aes.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/aria.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/asn1.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/asn1write.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/base64.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/bignum.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/build_info.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/camellia.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/ccm.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/chacha20.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/chachapoly.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/check_config.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/cipher.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/cmac.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/compat-2.x.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/config_psa.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/constant_time.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/ctr_drbg.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/debug.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/des.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/dhm.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/ecdh.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/ecdsa.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/ecjpake.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/ecp.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/entropy.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/error.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/gcm.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/hkdf.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/hmac_drbg.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/mbedtls_config.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/mbedtls_oc_platform.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/md.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/md5.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/memory_buffer_alloc.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/net_sockets.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/nist_kw.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/oid.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/pem.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/pk.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/pkcs12.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/pkcs5.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/platform.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/platform_time.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/platform_util.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/poly1305.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/private_access.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/psa_util.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/ripemd160.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/rsa.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/sha1.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/sha256.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/sha512.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/ssl.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/ssl_cache.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/ssl_ciphersuites.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/ssl_cookie.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/ssl_ticket.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/threading.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/timing.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/version.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/x509.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/x509_crl.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/x509_crt.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/mbedtls/x509_csr.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/psa" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto_builtin_composites.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto_builtin_primitives.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto_compat.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto_config.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto_driver_common.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto_driver_contexts_composites.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto_driver_contexts_primitives.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto_extra.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto_platform.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto_se_driver.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto_sizes.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto_struct.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto_types.h"
    "/home/jclee/Development/Matter/WS_Matter/iotivity-lite/deps/mbedtls/include/psa/crypto_values.h"
    )
endif()


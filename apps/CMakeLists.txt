project(iotivity-lite-apps)

function(oc_add_app_executable)
    set(options)
    set(oneValueArgs IDD TARGET)
    set(multiValueArgs DEPENDENCIES SOURCES)
    cmake_parse_arguments(OC_ADD_APP_EXECUTABLE "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    add_executable(${OC_ADD_APP_EXECUTABLE_TARGET} ${OC_ADD_APP_EXECUTABLE_SOURCES})
    target_compile_options(${OC_ADD_APP_EXECUTABLE_TARGET} PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    if(MINGW)
        target_compile_definitions(${OC_ADD_APP_EXECUTABLE_TARGET} PRIVATE "__USE_MINGW_ANSI_STDIO=(1)")
    endif()
    target_link_libraries(${OC_ADD_APP_EXECUTABLE_TARGET} PUBLIC ${OC_ADD_APP_EXECUTABLE_DEPENDENCIES})

    set(TARGET_STORAGE_FOLDER ${PROJECT_BINARY_DIR}/${OC_ADD_APP_EXECUTABLE_TARGET}_creds)
    file(MAKE_DIRECTORY ${TARGET_STORAGE_FOLDER})
    set_property(
        TARGET ${OC_ADD_APP_EXECUTABLE_TARGET}
        APPEND
        PROPERTY ADDITIONAL_CLEAN_FILES ${TARGET_STORAGE_FOLDER}
    )

    if(OC_IDD_API_ENABLED AND OC_ADD_APP_EXECUTABLE_IDD)
        get_filename_component(OC_ADD_APP_EXECUTABLE_IDD_FILENAME ${OC_ADD_APP_EXECUTABLE_IDD} NAME)
        add_custom_target(${OC_ADD_APP_EXECUTABLE_TARGET}-idd
            COMMAND
                ${CMAKE_COMMAND} -E copy ${OC_ADD_APP_EXECUTABLE_IDD} ${PROJECT_BINARY_DIR}
            BYPRODUCTS ${PROJECT_BINARY_DIR}/${OC_ADD_APP_EXECUTABLE_IDD_FILENAME}
        )
        add_dependencies(${OC_ADD_APP_EXECUTABLE_TARGET} ${OC_ADD_APP_EXECUTABLE_TARGET}-idd)
    endif()
endfunction()

# platform-independent applications
oc_add_app_executable(
    TARGET simpleserver-resourcedefaults
    SOURCES ${PROJECT_SOURCE_DIR}/simpleserver-resourcedefaults.c
    DEPENDENCIES server-static
)
oc_add_app_executable(
    TARGET simpleserver-TVAppAndAction
    SOURCES ${PROJECT_SOURCE_DIR}/simpleserver-TVAppAndAction.c
    DEPENDENCIES server-static
)
# old implemenation with boost
# -lboost_system -lcppnetlib-uri
oc_add_app_executable(
    TARGET smart_home_server_with_mock_swupdate
    SOURCES ${PROJECT_SOURCE_DIR}/smart_home_server_with_mock_swupdate.cpp
    DEPENDENCIES server-static
)

if(OC_CLOUD_ENABLED)
    oc_add_app_executable(
        TARGET cloud_client
        SOURCES ${PROJECT_SOURCE_DIR}/cloud_client.c
        DEPENDENCIES client-server-static
    )
    oc_add_app_executable(
        TARGET cloud_proxy
        SOURCES ${PROJECT_SOURCE_DIR}/cloud_proxy.c
        DEPENDENCIES client-server-static
        IDD ${PROJECT_SOURCE_DIR}/cloud_proxy_IDD.cbor
    )
    oc_add_app_executable(
        TARGET cloud_server
        SOURCES ${PROJECT_SOURCE_DIR}/cloud_server.c
        DEPENDENCIES client-server-static
    )
endif()

# platform-specific applications
if(UNIX)
    oc_add_app_executable(
        TARGET client_block_linux
        SOURCES ${PROJECT_SOURCE_DIR}/client_block_linux.c
        DEPENDENCIES client-static
    )
    oc_add_app_executable(
        TARGET client_certification_tests
        SOURCES ${PROJECT_SOURCE_DIR}/client_certification_tests.c
        DEPENDENCIES client-server-static
        IDD ${PROJECT_SOURCE_DIR}/client_certification_tests_IDD.cbor
    )
    oc_add_app_executable(
        TARGET client_collections_linux
        SOURCES ${PROJECT_SOURCE_DIR}/client_collections_linux.c
        DEPENDENCIES client-static
    )
    oc_add_app_executable(
        TARGET client
        SOURCES ${PROJECT_SOURCE_DIR}/client_linux.c
        DEPENDENCIES client-static
    )
    oc_add_app_executable(
        TARGET client_multithread_linux
        SOURCES ${PROJECT_SOURCE_DIR}/client_multithread_linux.c
        DEPENDENCIES client-static
    )
    oc_add_app_executable(
        TARGET multi_device_client
        SOURCES ${PROJECT_SOURCE_DIR}/multi_device_client_linux.c
        DEPENDENCIES client-static
    )
    oc_add_app_executable(
        TARGET multi_device_server
        SOURCES ${PROJECT_SOURCE_DIR}/multi_device_server_linux.c
        DEPENDENCIES server-static
    )
    oc_add_app_executable(
        TARGET secure_mcast_client
        SOURCES ${PROJECT_SOURCE_DIR}/secure_mcast_client.c
        DEPENDENCIES client-static
    )
    oc_add_app_executable(
        TARGET secure_mcast_server1
        SOURCES ${PROJECT_SOURCE_DIR}/secure_mcast_server1.c
        DEPENDENCIES server-static
    )
    oc_add_app_executable(
        TARGET secure_mcast_server2
        SOURCES ${PROJECT_SOURCE_DIR}/secure_mcast_server2.c
        DEPENDENCIES server-static
    )
    oc_add_app_executable(
        TARGET server_block_linux
        SOURCES ${PROJECT_SOURCE_DIR}/server_block_linux.c
        DEPENDENCIES server-static
    )
    oc_add_app_executable(
        TARGET server_certification_tests
        SOURCES ${PROJECT_SOURCE_DIR}/server_certification_tests.c
        DEPENDENCIES client-server-static
        IDD ${PROJECT_SOURCE_DIR}/server_certification_tests_IDD.cbor
    )
    oc_add_app_executable(
        TARGET server_collections_linux
        SOURCES ${PROJECT_SOURCE_DIR}/server_collections_linux.c
        DEPENDENCIES server-static
    )
    oc_add_app_executable(
        TARGET server
        SOURCES ${PROJECT_SOURCE_DIR}/server_linux.c
        DEPENDENCIES server-static
    )
    oc_add_app_executable(
        TARGET server_multithread_linux
        SOURCES ${PROJECT_SOURCE_DIR}/server_multithread_linux.c
        DEPENDENCIES server-static
    )
    oc_add_app_executable(
        TARGET server_rules
        SOURCES ${PROJECT_SOURCE_DIR}/server_rules.c
        DEPENDENCIES server-static
        IDD ${PROJECT_SOURCE_DIR}/server_rules_IDD.cbor
    )
    oc_add_app_executable(
        TARGET simpleclient
        SOURCES ${PROJECT_SOURCE_DIR}/simpleclient.c
        DEPENDENCIES client-static
    )
    oc_add_app_executable(
        TARGET simpleserver
        SOURCES ${PROJECT_SOURCE_DIR}/simpleserver.c
        DEPENDENCIES server-static
    )
    oc_add_app_executable(
        TARGET smart_home_server_linux
        SOURCES ${PROJECT_SOURCE_DIR}/smart_home_server_linux.c
        DEPENDENCIES server-static
        IDD ${PROJECT_SOURCE_DIR}/smart_home_server_linux_IDD.cbor
    )
    oc_add_app_executable(
        TARGET smart_lock
        SOURCES ${PROJECT_SOURCE_DIR}/smart_lock_linux.c
        DEPENDENCIES client-static
    )
    oc_add_app_executable(
        TARGET temp_sensor
        SOURCES ${PROJECT_SOURCE_DIR}/temp_sensor_client_linux.c
        DEPENDENCIES client-static
    )

    if(OC_SECURITY_ENABLED AND OC_PKI_ENABLED)
        oc_add_app_executable(
            TARGET simpleserver_pki
            SOURCES ${PROJECT_SOURCE_DIR}/simpleserver_pki.c
            DEPENDENCIES server-static
        )
    endif()

    if(OC_CLOUD_ENABLED)
        oc_add_app_executable(
            TARGET cloud_tests
            SOURCES ${PROJECT_SOURCE_DIR}/cloud_certification_tests.c
            DEPENDENCIES client-server-static
        )
    endif()

    if(OC_PUSH_ENABLED)
        oc_add_app_executable(
            TARGET push_configurator_multithread_linux
            SOURCES ${PROJECT_SOURCE_DIR}/push_configurator_multithread_linux.c
            DEPENDENCIES client-server-static
        )
        oc_add_app_executable(
            TARGET push_originserver_multithread_linux
            SOURCES ${PROJECT_SOURCE_DIR}/push_originserver_multithread_linux.c
            DEPENDENCIES client-server-static
        )
        oc_add_app_executable(
            TARGET push_targetserver_multithread_linux
            SOURCES ${PROJECT_SOURCE_DIR}/push_targetserver_multithread_linux.c
            DEPENDENCIES client-server-static
        )
    endif()

    if(EXISTS ${PROJECT_SOURCE_DIR}/device_builder_server.c)
        oc_add_app_executable(
            TARGET device_builder_server
            SOURCES ${PROJECT_SOURCE_DIR}/device_builder_server.c
            DEPENDENCIES client-server-static
        )
    endif()
elseif(WIN32)
    oc_add_app_executable(
        TARGET simpleclient
        SOURCES ${PROJECT_SOURCE_DIR}/simpleclient_windows.c
        DEPENDENCIES client-server-static
    )
    oc_add_app_executable(
        TARGET simpleserver
        SOURCES ${PROJECT_SOURCE_DIR}/simpleserver_windows.c
        DEPENDENCIES client-server-static
    )
endif()

if(OC_INTROSPECTION_ENABLED)
    add_executable(introspectionclient
        ${PROJECT_SOURCE_DIR}/introspectionclient.c
    )
    target_compile_options(introspectionclient PRIVATE ${PRIVATE_COMPILE_OPTIONS})
    target_link_libraries(introspectionclient client-static)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/introspectionclient_creds)

    if(OC_IDD_API_ENABLED)
        # copy introspection files, used by certification applications.
        set(idd_files
            ${PROJECT_SOURCE_DIR}/server_certification_tests_IDD.cbor
            ${PROJECT_SOURCE_DIR}/client_certification_tests_IDD.cbor
            ${PROJECT_SOURCE_DIR}/server_rules_IDD.cbor
            ${PROJECT_SOURCE_DIR}/cloud_proxy_IDD.cbor
            ${PROJECT_SOURCE_DIR}/smart_home_server_linux_IDD.cbor
        )
        add_custom_target(copy-idd-files
            COMMAND ${CMAKE_COMMAND} -E copy ${idd_files} ${PROJECT_BINARY_DIR}
        )
        add_dependencies(client-server-static copy-idd-files)
    endif()
endif()

# copy credentials, used by example applications.
add_custom_target(copy-pki-certs ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${PROJECT_SOURCE_DIR}/pki_certs
    ${PROJECT_BINARY_DIR}/pki_certs
)
add_dependencies(client-server-static copy-pki-certs)

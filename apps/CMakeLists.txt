project(iotivity-lite-apps)

add_executable(simpleserver
    ${PROJECT_SOURCE_DIR}/simpleserver.c
    ${iotivity-lite_SOURCE_DIR}/api/oc_introspection.c
)
target_link_libraries(simpleserver
    iotivity-server-client
    pthread
    m
)

add_executable(simpleserver_pki
    ${PROJECT_SOURCE_DIR}/simpleserver_pki.c
    ${iotivity-lite_SOURCE_DIR}/api/oc_introspection.c
)
target_link_libraries(simpleserver_pki
    iotivity-server-client
    pthread
    m
)

add_executable(simpleclient
    ${PROJECT_SOURCE_DIR}/simpleclient.c
    ${iotivity-lite_SOURCE_DIR}/api/oc_introspection.c
)
target_link_libraries(simpleclient
    iotivity-client
    pthread
    m
)

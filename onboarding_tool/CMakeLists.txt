project(onboarding_tool)

add_executable(onboarding_tool
    ${PROJECT_SOURCE_DIR}/obtmain.c
    ${iotivity-lite_SOURCE_DIR}/api/oc_introspection.c
)

target_link_libraries(onboarding_tool
    iotivity-client
    pthread
    m
)
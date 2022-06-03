project(onboarding_tool)

if(UNIX AND OC_DYNAMIC_ALLOCATION_ENABLED AND OC_SECURITY_ENABLED AND OC_PKI_ENABLED)
    add_executable(onboarding_tool
        ${PROJECT_SOURCE_DIR}/obtmain.c
    )
    target_link_libraries(onboarding_tool PRIVATE client-static)

    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/onboarding_tool_creds)

    # copy credentials
    add_custom_target(copy-pki-certs-obt ALL
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${PROJECT_SOURCE_DIR}/../apps/pki_certs
        ${PROJECT_BINARY_DIR}/pki_certs
    )
    add_dependencies(onboarding_tool copy-pki-certs-obt)
endif()
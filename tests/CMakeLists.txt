project(iotivity-lite-tests)

add_executable(client_init_linux_test
    ${PROJECT_SOURCE_DIR}/client_init_linux.c
)
target_compile_options(client_init_linux_test PRIVATE ${PRIVATE_COMPILE_OPTIONS})
target_link_libraries(client_init_linux_test PRIVATE client-static)

add_executable(server_init_linux_test
    ${PROJECT_SOURCE_DIR}/server_init_linux.c
)
target_compile_options(server_init_linux_test PRIVATE ${PRIVATE_COMPILE_OPTIONS})
target_link_libraries(server_init_linux_test PRIVATE server-static)

add_executable(client_get_linux_test
    ${PROJECT_SOURCE_DIR}/client_get_linux.c
)
target_compile_options(client_get_linux_test PRIVATE ${PRIVATE_COMPILE_OPTIONS})
target_link_libraries(client_get_linux_test PRIVATE client-server-static)

find_package(PythonInterp)
if(PYTHONINTERP_FOUND)
    set(test_bins "./client_init_linux_test" "./server_init_linux_test")
    # client_get_linux_test hangs
    #list(APPEND test_bins "./client_get_linux_test")
    add_custom_target(check
        COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/../tools/check.py --tests="${test_bins}"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Run tests ${test_bins}"
    )
endif(PYTHONINTERP_FOUND)
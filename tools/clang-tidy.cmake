cmake_minimum_required (VERSION 3.10)

include_guard(GLOBAL)

if(UNIX AND OC_CLANG_TIDY_ENABLED)
    file(GLOB iotivity_directories LIST_DIRECTORIES true "${PROJECT_SOURCE_DIR}/*")

    set(iotivity_dirnames "")
    foreach(dir ${iotivity_directories})
        if (NOT IS_DIRECTORY "${dir}")
            continue()
        endif()

        get_filename_component(dirname "${dir}" NAME_WE)
        if (dirname)
            # skip hidden directories
            if (dirname MATCHES "^\\.")
                continue()
            endif()

            # skip third-party libs
            if (dirname STREQUAL "deps")
                continue()
            endif()

            list(APPEND iotivity_dirnames ${dirname})
        endif()
    endforeach()

    if(iotivity_dirnames)
        get_filename_component(project_source_dirname "${PROJECT_SOURCE_DIR}" NAME_WE)
        string(REPLACE ";" "|" iotivity_dirs_regexp "${iotivity_dirnames}")
        set(IOTIVITY_DIR_NAMES_REGEX ".*/${project_source_dirname}/(${iotivity_dirs_regexp})/.*")
    else()
        set(IOTIVITY_DIR_NAMES_REGEX ".*")
    endif()

    configure_file(
        "${PROJECT_SOURCE_DIR}/tools/.clang-tidy.in"
        "${PROJECT_SOURCE_DIR}/.clang-tidy"
        @ONLY)
endif()

# enable clang-tidy before defining targets you want to run analysis on
macro(oc_enable_clang_tidy)
    if(UNIX AND OC_CLANG_TIDY_ENABLED)
        # use clang-tidy during compilation if its available
        find_program(CLANG_TIDY_BIN clang-tidy)
        if(CLANG_TIDY_BIN)
            set(CMAKE_C_CLANG_TIDY ${CLANG_TIDY_BIN})
            set(CMAKE_CXX_CLANG_TIDY ${CMAKE_C_CLANG_TIDY})
        else()
            message(STATUS "clang-tidy not installed")
        endif()
    endif()
endmacro()

# disable clang-tidy before defining targets you want to skip analysis on
macro(oc_disable_clang_tidy)
    set(CMAKE_C_CLANG_TIDY "")
    set(CMAKE_CXX_CLANG_TIDY "")
endmacro()

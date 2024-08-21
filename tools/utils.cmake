include_guard(GLOBAL)

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

# function oc_add_compile_options([GLOBAL] [IX_CXX] FLAGS [flags...])
#
# Arguments:
#   GLOBAL   (option) flags are added as global compilation options
#   FLAGS    list of flags to check and add for both C and C++
#   CFLAGS   list of flags to check and add for C
#   CXXFLAGS list of flags to check and add for C++
#
# Side-effect: C_COMPILER_SUPPORTS_${flag_name} / CXX_COMPILER_SUPPORTS_${flag_name}
# is created and set to ON/OFF based on the result of the check. This variable
# can be used in the context of the caller.
function(oc_add_compile_options)
    set(options GLOBAL)
    set(oneValueArgs)
    set(multiValueArgs CFLAGS CXXFLAGS FLAGS)
    cmake_parse_arguments(OC_ADD_COMPILE_OPTIONS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    foreach(flag IN LISTS OC_ADD_COMPILE_OPTIONS_FLAGS OC_ADD_COMPILE_OPTIONS_CFLAGS)
        string(REPLACE "-" "_" flag_name ${flag})
        string(REPLACE "=" "_" flag_name ${flag_name})
        string(TOUPPER ${flag_name} flag_name)
        set(flag_name "C_COMPILER_SUPPORTS${flag_name}")
        unset(${flag_name})
        check_c_compiler_flag(${flag} ${flag_name})
        if((OC_ADD_COMPILE_OPTIONS_GLOBAL) AND (${${flag_name}}))
            add_compile_options($<$<COMPILE_LANGUAGE:C>:${flag}>)
        endif()
        set(${flag_name} ${${flag_name}} PARENT_SCOPE)
    endforeach()

    foreach(flag IN LISTS OC_ADD_COMPILE_OPTIONS_FLAGS OC_ADD_COMPILE_OPTIONS_CXXFLAGS)
        string(REPLACE "-" "_" flag_name ${flag})
        string(REPLACE "=" "_" flag_name ${flag_name})
        string(TOUPPER ${flag_name} flag_name)
        set(flag_name "CXX_COMPILER_SUPPORTS${flag_name}")
        unset(${flag_name})
        check_cxx_compiler_flag(${flag} ${flag_name})
        if((OC_ADD_COMPILE_OPTIONS_GLOBAL) AND (${${flag_name}}))
            add_compile_options($<$<COMPILE_LANGUAGE:CXX>:${flag}>)
        endif()
        set(${flag_name} ${${flag_name}} PARENT_SCOPE)
    endforeach()
endfunction()

function(oc_set_maximum_log_level level outlevel)
    if(("${level}" STREQUAL "DISABLED") OR ("${level}" STREQUAL ""))
        set(level_int -1)
    elseif("${level}" STREQUAL "ERROR")
        set(level_int 3)
    elseif("${level}" STREQUAL "WARNING")
        set(level_int 4)
    elseif("${level}" STREQUAL "NOTICE")
        set(level_int 5)
    elseif("${level}" STREQUAL "INFO")
        set(level_int 6)
    elseif("${level}" STREQUAL "DEBUG")
        set(level_int 7)
    elseif("${level}" STREQUAL "TRACE")
        set(level_int 8)
    else()
        message(FATAL_ERROR "Invalid log level string: ${level}")
    endif()

    # assign to output variable
    set(${outlevel} ${level_int} PARENT_SCOPE)
endfunction()

#!/bin/bash
# ****************************************************************************
# *
# * Copyright 2018 Samsung Electronics All Rights Reserved.
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# *
# * http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing,
# * software distributed under the License is distributed on an
# * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# * either express or implied. See the License for the specific
# * language governing permissions and limitations under the License.
# *
# ****************************************************************************/

#required tool
#sudo apt-get install valgrind
#sudo apt-get install massif-visualizer

set -e
set -x

function printUsage()
{
    echo
    echo -e "Memory Profile script usage:"
    echo -e "$ $0 -mt -mp <sampleappname>"
    echo
    echo -e "    -mt: wil memory trace of given sampleapp"
    echo -e "    -mp: wil make memory profile of given sampleapp"
    echo
    exit
}

function doReadFromFile()
{
    tail "${iotivity}/memory_profile/$memoryfile"
}

function doMemoryProfile()
{
    for var in "${POSITIONAL[@]}"
    do
        valgrind --tool=massif --time-unit=B --stacks=yes --heap=yes ./$var
        massiffile="massif.out.$(echo "$var" | tr '/' ',').log.txt"

        ms_print massif.out.* >> "${iotivity}/memory_profile/$massiffile"
        memoryfile="massif.out.$(echo "$var" | tr '/' ',').peak.log.txt"
        awk '/KB/{getline;gsub("[:^]","");print $1}' "${iotivity}/memory_profile/$massiffile" >> "${iotivity}/memory_profile/$memoryfile"

        mv massif.out.* "${iotivity}/memory_profile/"
    done
}
function doUpdateConfirFile()
{
    REPLACEMENT_VALUE=$1
    sed -i "s/\($TARGET_KEY *= *\).*/\1$REPLACEMENT_VALUE/" "$CONFIG_FILE"
}

function doMemoryTrace()
{
    doUpdateConfirFile 0
    make clean
    make MEMTRACE=1
    make qa_test

    for var in "${POSITIONAL[@]}"
    do
        unrechablememoryfile="memory_trace.out.$(echo "$var" | tr '/' ',').log.txt"
        ./$var >> "${iotivity}/memory_profile/$unrechablememoryfile"
    done

    doUpdateConfirFile 1
}

function initialize()
{
    POSITIONAL=()
    MEMTRACE="no"
    MEMPROFILE="no"
    iotivity="$PWD"
    TARGET_KEY="TEST_RUN"

    root_dir="${iotivity}/../.."
    linux_dir="${root_dir}/port/linux"
    test_dir="${root_dir}/tests/port/linux"
    cd "$linux_dir"
    CONFIG_FILE="$test_dir/configFile.txt"
    echo -e "CONFIG_FILE = $CONFIG_FILE"
    #for script run need to remove previous file
    #rm -rf "${iotivity}/memory_profile"
    #rm -rf massif.out.*

    if [ -d "${iotivity}/memory_profile" ];
    then
        echo -e "Exists"
    else
        mkdir "${iotivity}/memory_profile"
    fi
}

function configure()
{
    while [[ $# -gt 0 ]]
    do
    key="$1"
    case $key in
        h|-h|help|-help|--help|?)  PrintUsage;;
        -mt|--memorytrace)
        MEMTRACE="yes"
        shift # past argument
        ;;
        -mp|--memoryprofile)
        MEMPROFILE="yes"
        shift # past argument
        ;;
        --default)
        DEFAULT=YES
        shift # past argument
        ;;
        *)    # unknown option
        POSITIONAL+=("$1") # save it in an array for later
        shift # past argument
        ;;
    esac
    done
    set -- "${POSITIONAL[@]}" # restore positional parameters

    echo MEMTRACE  = "${MEMTRACE}"
    echo MEMPROFILE     = "${MEMPROFILE}"
}

initialize
configure "$@"

if [ "${MEMPROFILE}" = 'yes' ]
then
    doMemoryProfile
fi

# make with memtrace to get unreachable memory with the address function
if [ "${MEMTRACE}" = 'yes' ]
then
    doMemoryTrace
fi

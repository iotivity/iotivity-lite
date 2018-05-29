#!/bin/bash -x
BASE_DIRECTORY=$(cd `dirname $0` && pwd)
INPUT_JSON_FILE=${1:-${BASE_DIRECTORY}/device_specification.json}
OUTPUT_C_HEADER=${2:-${BASE_DIRECTORY}/device_specification.h}

SED_TOOL=`which sed`

if(( -f ${OUTPUT_C_HEADER} )); then
    rm ${OUTPUT_C_HEADER}
fi

eval "${SED_TOOL} ':a;N;\$!ba;s/\n/ /g;' ${INPUT_JSON_FILE} > ${OUTPUT_C_HEADER}"
eval "${SED_TOOL} -i -e 's/\ //g' -e 's/\"/\\\\\"/g' ${OUTPUT_C_HEADER}"
eval "${SED_TOOL} -i -e 's/\(.*\)/\/* Auto Generated File (DO NOT EDIT BY HAND) *\/\nchar\* device_specification = \"\1\";/' ${OUTPUT_C_HEADER}"

cat ${OUTPUT_C_HEADER}

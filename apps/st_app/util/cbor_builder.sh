#!/bin/bash
FILE=$1
FILENAME=$(echo "$FILE" | sed 's/\.[^\.]*$//')
CBOR="st_device_def"
HEADER="st_device_def.h"
sh -c "./json2cbor ${FILE} > ${CBOR}"
sh -c "xxd -i ${CBOR} > ../${HEADER}"
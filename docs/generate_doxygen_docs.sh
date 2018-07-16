#!/bin/bash

set -e
#Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
NO_COLOUR="\033[0m"

#Defaults
IOTIVITY_BASE="$(git rev-parse --show-toplevel)"
IOTIVITY_DOCS="${IOTIVITY_BASE}/docs"
TIME_STAMP="$(date -u +%Y%b%d)"
COMMIT_HASH="$(git rev-parse --short samsung)"
OUTPUT_DOCS=("iotivity_lite" "iotivity_st_app_fw_api")

pushd ${IOTIVITY_DOCS}

for item in "${OUTPUT_DOCS[@]}"; do
  echo -e "Deleting  ${RED}${IOTIVITY_DOCS}/${item}${NO_COLOUR}"
  rm -rf ${IOTIVITY_DOCS}/${item}

  echo -e "Creating ${GREEN}Doxygen Documentation ${item}${NO_COLOUR}"
  doxygen "${item}.doxyfile"

  echo -e "Compressing ${BLUE}Doxygen Documentation ${item} to ${item}_${TIME_STAMP}_${COMMIT_HASH}.tar.gz ${NO_COLOUR}"
  tar cvzf "${item}_${TIME_STAMP}_${COMMIT_HASH}.tar.gz" "${item}"
done

popd

#!/bin/bash

# TODO: read releases from github
RELEASES=(
  # start index=0
  2.2.4.2 2.2.4.3
  # start index=2
  2.2.5 2.2.5.1 2.2.5.2 2.2.5.3 2.2.5.4 2.2.5.5
)

PACKAGES=(
    "cloud-server"
    "cloud-server-debug"
    "cloud-server-discovery-resource-observable"
    "cloud-server-discovery-resource-observable-debug"
)

PACKAGE_RELEASES=("${RELEASES[@]}")

if [[ -z "${PACKAGE}" ]]; then
    echo "ERROR: package not set" >&2
    exit 1
fi

if [[ "${PACKAGE}" == "cloud-server" ]]; then
    # all
    :
fi

if [[ "${PACKAGE}" == "cloud-server-debug" ]]; then
    # all
    :
fi

if [[ "${PACKAGE}" == "cloud-server-discovery-resource-observable" ]]; then
    # all
    :
fi

if [[ "${PACKAGE}" == "cloud-server-discovery-resource-observable-debug" ]]; then
    # all
    :
fi


MISSING_PACKAGES=()
for i in "${PACKAGE_RELEASES[@]}"; do
    echo "Checking ${PACKAGE}:${i}"
    if docker pull ghcr.io/iotivity/iotivity-lite/${PACKAGE}:${i}; then
        docker rmi ghcr.io/iotivity/iotivity-lite/${PACKAGE}:${i} > /dev/null
    else
        echo "ERROR: ${PACKAGE}:${i} not found"
        MISSING_RELEASES+=(${i})
    fi
done

echo ""
echo "Missing releases:"
printf '%s ' "${MISSING_RELEASES[@]}"
echo ""

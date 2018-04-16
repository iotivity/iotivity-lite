#!/bin/sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2015-2016, ARM Limited, All Rights Reserved
#
# Purpose
#
# This script determines ROM size (or code size) for the standard mbed TLS
# configurations, when built for a Cortex M3/M4 target.
#
# Configurations included:
#   default    include/mbedtls/config.h
#   yotta      yotta/module/mbedtls/config.h
#   thread     configs/config-thread.h
#   suite-b    configs/config-suite-b.h
#   psk        configs/config-ccm-psk-tls1_2.h
#
# Usage: footprint.sh
#
set -eu

CONFIG_H='include/mbedtls/config.h'

if [ -r $CONFIG_H ]; then :; else
    echo "$CONFIG_H not found" >&2
    echo "This script needs to be run from the root of" >&2
    echo "a git checkout or uncompressed tarball" >&2
    exit 1
fi

if grep -i cmake Makefile >/dev/null; then
    echo "Not compatible with CMake" >&2
    exit 1
fi

if which arm-none-eabi-gcc >/dev/null 2>&1; then :; else
    echo "You need the ARM-GCC toolchain in your path" >&2
    echo "See https://launchpad.net/gcc-arm-embedded/" >&2
    exit 1
fi

ARMGCC_FLAGS='-Os -march=armv7-m -mthumb'
OUTFILE='00-footprint-summary.txt'

log()
{
    echo "$@"
    echo "$@" >> "$OUTFILE"
}

doit()
{
    NAME="$1"
    FILE="$2"

    log ""
    log "$NAME ($FILE):"

    cp $CONFIG_H ${CONFIG_H}.bak
    if [ "$FILE" != $CONFIG_H ]; then
        cp "$FILE"  $CONFIG_H
    fi

    {
        scripts/config.pl unset MBEDTLS_NET_C || true
        scripts/config.pl unset MBEDTLS_TIMING_C || true
        scripts/config.pl unset MBEDTLS_FS_IO || true
        scripts/config.pl --force set MBEDTLS_NO_PLATFORM_ENTROPY || true
    } >/dev/null 2>&1

    make clean >/dev/null
    CC=arm-none-eabi-gcc AR=arm-none-eabi-ar LD=arm-none-eabi-ld \
        CFLAGS="$ARMGCC_FLAGS" make lib >/dev/null

    OUT="size-${NAME}.txt"
    arm-none-eabi-size -t library/libmbed*.a > "$OUT"
    log "$( head -n1 "$OUT" )"
    log "$( tail -n1 "$OUT" )"

    cp ${CONFIG_H}.bak $CONFIG_H
}

# truncate the file just this time
echo "(generated by $0)" > "$OUTFILE"
echo "" >> "$OUTFILE"

log "Footprint of standard configurations (minus net_sockets.c, timing.c, fs_io)"
log "for bare-metal ARM Cortex-M3/M4 microcontrollers."

VERSION_H="include/mbedtls/version.h"
MBEDTLS_VERSION=$( sed -n 's/.*VERSION_STRING *"\(.*\)"/\1/p' $VERSION_H )
if git rev-parse HEAD >/dev/null; then
    GIT_HEAD=$( git rev-parse HEAD | head -c 10 )
    GIT_VERSION=" (git head: $GIT_HEAD)"
else
    GIT_VERSION=""
fi

log ""
log "mbed TLS $MBEDTLS_VERSION$GIT_VERSION"
log "$( arm-none-eabi-gcc --version | head -n1 )"
log "CFLAGS=$ARMGCC_FLAGS"

# creates the yotta config
yotta/create-module.sh >/dev/null

doit default    include/mbedtls/config.h
doit yotta      yotta/module/mbedtls/config.h
doit thread     configs/config-thread.h
doit suite-b    configs/config-suite-b.h
doit psk        configs/config-ccm-psk-tls1_2.h

zip mbedtls-footprint.zip "$OUTFILE" size-*.txt >/dev/null

#!/usr/bin/make -f
# -*- makefile -*-
# ex: set tabstop=4 noexpandtab:
#{
# Copyright 2018 Samsung Electronics France SAS, All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#}

default: all
	sync

top_rel_dir?=../../..
top_dir?=${CURDIR}/${top_rel_dir}
extra_dir?=${top_dir}/deps

app_dir?=${top_dir}/port/tizenrt

tizenrt_dir?=${top_dir}/deps/TizenRT
os_dir?=${tizenrt_dir}/os
os_url?=https://github.com/Samsung/TizenRT
os_branch?=2.0_GBM_M1
os_machine?=artik053
os_image_type?=nettest
configure_file?=${os_dir}/.config
os_external_makefile?=${tizenrt_dir}/external/Makefile

toolchain_file?=${toolchain_package}-${toolchain_host}.tar.bz2
toolchain_url?=https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu-rm/6_1-2017q1/${toolchain_file}
toolchain_web_url?=https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads/6-2017-q1-update
toolchain_abi?=arm-none-eabi
toolchain_version?=6-2017-q1-update
toolchain_host?=linux
toolchain_dir?=${extra_dir}/${toolchain_package}
toolchain_package?=gcc-${toolchain_abi}-${toolchain_version}
toolchain_bin?=${toolchain_dir}/bin

CROSSCOMPIL?=${toolchain_bin}/${toolchain_abi}-
CC=${CROSSCOMPIL}gcc
export CC
PATH:=${toolchain_bin}:${PATH}
export PATH

prep_files+=${CC}
prep_files+=${tizenrt_dir}/tmp/done.log
prep_files+=${tizenrt_dir}/external/iotivity-constrained.Kconfig.tmp
prep_files+=${tizenrt_dir}/external/iotivity-constrained.mk.tmp
prep_files+=${top_dir}/deps/tinycbor/LICENSE
prep_files+=${top_dir}/deps/tinycbor/tmp/done.log

all?=prep configure build

${tizenrt_dir}:
	git clone --depth 1 --recursive -b "${os_branch}" "${os_url}" "$@"

${tizenrt_dir}/external/iotivity-constrained.mk.tmp: iotivity-constrained.mk ${os_external_makefile}.orig
	cp "$<" "$@.tmp"
	cp "$@.tmp" "${os_external_makefile}"
	mv "$@.tmp" "$@"
	touch "$@"

${os_external_makefile}.orig: ${os_external_makefile}
	ls $@ || cp -av $< $@

${top_dir}/deps/tinycbor/%:
	${MAKE} -C "${top_dir}/tests" prep

tinycbor_patches?=$(sort $(wildcard ${top_dir}/patches/tinycbor/*.patch))
${top_dir}/deps/tinycbor/tmp/done.log: ${top_dir}/deps/tinycbor/. ${tinycbor_patches}
	cd ${<D} && for patch in ${tinycbor_patches} ; do patch -r - -s -N -p1 < $${patch} ; done
	mkdir -p ${@D}
	echo "Patches applied in $^" > ${@}


${tizenrt_dir}/external/iotivity-constrained.Kconfig.tmp: ${CURDIR}/iotivity-constrained.Kconfig ${tizenrt_dir}
	grep 'iotivity-constrained' "${tizenrt_dir}/external/Kconfig" \
  || echo "source \"$<\"" >> "${tizenrt_dir}/external/Kconfig"
	cp -av "${tizenrt_dir}/external/Kconfig" "$@"

${tizenrt_dir}/%: ${tizenrt_dir}
	ls "$@"

IOTIVITY_CONSTRAINED_BASE_DIR?=${CURDIR}/../../..
export IOTIVITY_CONSTRAINED_BASE_DIR

#${tizenrt_dir}/external/iotivity-constrained:
#	ls $@ || ln -fs ${CURDIR}/../.. $@

build: ${tizenrt_dir}/build/output/bin/tinyara_head.bin
	ls $<

${tizenrt_dir}/build/output/bin/tinyara_head.bin: ${os_dir}/.config
	${MAKE} -C "${<D}"
	ls -l $@

${configure_file}: ${tizenrt_dir} ${CC}
	ls "$@" || ${MAKE} rule/configure

configure: ${configure_file}
	ls "$<"

rule/configure: ${tizenrt_dir}/os/Make.defs
	ls "$<"

${tizenrt_dir}/os/Make.defs: ${tizenrt_dir}/os/tools ${CC}
	cd "$<" && ./configure.sh ${os_machine}/${os_image_type}
	echo "CONFIG_ENABLE_IOTIVITY_CONSTRAINED=y" >> ${configure_file}
	echo "CONFIG_IOTLITE_EASYSETUP=y" >> ${configure_file}

${tizenrt_dir}/tmp/done.log: ${tizenrt_dir}/os/Make.defs $(wildcard ${tizenrt_dir}/build/configs/*/*/Make.defs)
	sed -e 's/-Werror//g' -i $^
	mkdir -p ${@D}
	echo "Patches applied in $^" > "$@"
	echo "TODO: Enable Werror again on next TizenRT update"

prep: ${prep_files}
	ls $^

${toolchain_dir}:
	mkdir -p "${@D}"
	cd "${@D}" && curl -sL "${toolchain_url}" | tar xj
	ls "$@"
	ls "${toolchain_bin}"
	ls "${CC}"
	-file "${CC}"
	"${CC}" --version

${toolchain_dir}/%: ${toolchain_dir}
	ls "$@"

gcc-arm-embedded/setup: ${CC}
	$< --version
	@echo "PATH=${PATH}"

gcc-arm-embedded/setup/debian:
	sudo apt-get install -y libc6-i386

gcc-arm-embedded/setup/debian/stretch/sid:
	sudo apt-get install binutils-arm-none-eabi

all: ${all}
	sync

menuconfig: ${os_dir}
	${MAKE} -C "$<" "$@"

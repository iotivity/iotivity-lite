#!/usr/bin/make -f
# -*- makefile -*-
# ex: set tabstop=4 noexpandtab:
#{
# Copyright 2018 Samsung Electronics France SAS
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

top_rel_dir?=../../..
top_dir?=${CURDIR}/${top_rel_dir}
extra_dir?=${top_dir}/deps

app_dir?=${top_dir}/port/tizenrt

os_dir?=${top_dir}/deps/TizenRT
os_url?=https://github.com/Samsung/TizenRT
os_branch?=1.1_Public_Release
os_machine?=artik053
configure_file?=${os_dir}/os/.config

toolchain_file?=${toolchain_package}-2015q3-20150921-linux.tar.bz2
toolchain_url?=https://launchpad.net/gcc-arm-embedded/4.9/4.9-2015-q3-update/+download/gcc-arm-none-eabi-4_9-2015q3-20150921-linux.tar.bz2
toolchain_web_url?=https://launchpad.net/gcc-arm-embedded/4.9/4.9-2015-q3-update
toolchain_abi?=arm-none-eabi
toolchain_dir?=${extra_dir}/${toolchain_package}
toolchain_package?=gcc-${toolchain_abi}-4_9-2015q3
toolchain_bin?=${toolchain_dir}/bin

CROSSCOMPIL?=${toolchain_bin}/${toolchain_abi}-
CC=${CROSSCOMPIL}gcc
export CC
PATH:=${toolchain_bin}:${PATH}
export PATH

prep_files+=${CC}

${os_dir}:
	git clone --depth 1 --recursive -b "${os_branch}" "${os_url}" "$@"

prep_files+=${os_dir}/external/iotivity-constrained.mk

${os_dir}/external/iotivity-constrained.mk: ${os_dir}/external/Makefile
	cp "${CURDIR}/iotivity-constrained.mk" "$@.tmp"
	cp "$@.tmp" "$<"
	mv "$@.tmp" "$@"
	touch "$@"

prep_files+=${os_dir}/external/iotivity-constrained.Kconfig

prep_files+=${top_dir}/deps/tinycbor/LICENSE

${top_dir}/deps/tinycbor/%:
	${MAKE} -C "${top_dir}/tests" prep

${os_dir}/external/iotivity-constrained.Kconfig: ${CURDIR}/iotivity-constrained.Kconfig ${os_dir}
	@echo "source \"$<\"" >> ${os_dir}/external/Kconfig
	cp -av "${os_dir}/external/Kconfig" "$@"

${os_dir}/%: ${os_dir}
	ls "$@"

build: ${os_dir} ${os_dir}/os/.config
	${MAKE} -C "$</os"

${configure_file}: ${os_dir} prep
	ls "$@" || ${MAKE} rule/configure

configure: ${configure_file}
	ls "$<"

rule/configure: ${os_dir}/os/tools
	cd "$<" && ./configure.sh ${os_machine}/minimal
	echo "CONFIG_ENABLE_IOTIVIVIY_CONSTRAINED=y" >> ${configure_file}

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

all: gcc-arm-embedded/setup prep configure build
	sync

menuconfig: ${os_dir}/os
	${MAKE} -C "$<" "$@"


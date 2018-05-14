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
os_revision?=13aa00554e0b7a416ff3c453bf3192c40c71ae86
os_branch?=master
os_branch?=1.1_Public_Release
os_machine?=artik055s
os_image_type?=iotlite
os_image_type?=${os_machine}
os_image_type?=${base_config_name}
os_image_type?=minimal
configure_file?=${os_dir}/.config
os_external_makefile?=${tizenrt_dir}/external/Makefile

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
prep_files+=${tizenrt_dir}/external/iotivity-constrained.Kconfig.tmp
prep_files+=${tizenrt_dir}/external/iotivity-constrained.mk.tmp
prep_files+=${top_dir}/deps/tinycbor/LICENSE
prep_files+=${tizenrt_dir}/apps/iotlite_apps
base_config_name?=iotlite
base_config_name?=${os_machine}
prep_files+=${tizenrt_dir}/build/configs/${os_machine}/${base_config_name}
#TODO
prep_files+=${tizenrt_dir}/external/iotivity-constrained/iotivity-constrained
prep_files+=${tizenrt_dir}/external/iotivity-constrained/Make.defs
prep_files+=${tizenrt_dir}/external/iotivity-constrained/Makefile
git?=git
all?=prep configure build


${tizenrt_dir}:
	${git} clone --depth 1 --recursive -b "${os_branch}" "${os_url}" ${tizenrt_dir}

TODO/tizenrt:
	${git} clone --recursive -b "${os_branch}" "${os_url}" ${tizenrt_dir}
	cd "${tizenrt_dir}" && git reset --hard "${os_revision}"

${tizenrt_dir}/external/iotivity-constrained.mk.tmp: iotivity-constrained.mk ${os_external_makefile}.orig
	cp "$<" "$@.tmp"
	cp "$@.tmp" "${os_external_makefile}"
	mv "$@.tmp" "$@"
	touch "$@"

${os_dir}: ${tizenrt_dir}
	ls $@

${os_external_makefile}.orig: ${os_external_makefile}
	ls $@ || cp -av $< $@

${top_dir}/deps/tinycbor/%:
	${MAKE} -C "${top_dir}/tests" prep

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

build: ${os_dir}/.config
	${MAKE} -C "${<D}"

${configure_file}: ${tizenrt_dir} prep
	ls "$@" || ${MAKE} rule/configure

configure: ${configure_file}
	ls "$<"

rule/configure: ${tizenrt_dir}/os/tools
	cd "$<" && ./configure.sh ${os_machine}/${os_image_type}
	echo "CONFIG_ENABLE_IOTIVITY_CONSTRAINED=y" >> ${configure_file}
	echo "CONFIG_IOTLITE_EASYSETUP=y" >> ${configure_file}

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

${tizenrt_dir}/apps/iotlite_apps: ${top_dir}/port/tizenrt/iotlite_apps ${tizenrt_dir}
	ls $@ || cp -rfva $< $@

${tizenrt_dir}/build/configs/${os_machine}/${os_image_type}: ${top_dir}/tests/port/tizenrt/configs/${os_machine}/${os_image_type} ${tizenrt_dir}
	ls $@ || ln -fs $< $@

${tizenrt_dir}/external/iotivity-constrained: ${top_dir} ${tizenrt_dir}
	ls $@ || ln -fs $< $@

${tizenrt_dir}/external/iotivity-constrained/iotivity-constrained: ${tizenrt_dir}/external/iotivity-constrained
	ls $@ || ln -fs . $@

${tizenrt_dir}/external/iotivity-constrained/Make.defs: ${top_dir}/port/tizenrt/scripts/Make.defs ${tizenrt_dir}/external/iotivity-constrained
	ls $@ || ln -fs $< $@

${tizenrt_dir}/external/iotivity-constrained/Makefile: ${top_dir}/port/tizenrt/scripts/Makefile ${tizenrt_dir}/external/iotivity-constrained
	ls $@ || ln -fs $< $@


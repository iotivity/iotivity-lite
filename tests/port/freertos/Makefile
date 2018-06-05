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

top_dir?=../../..
extra_dir?=${CURDIR}/${top_dir}/deps

port?=freertos
export port

os_url?=https://github.com/espressif/esp-idf
os_dir?=${extra_dir}/esp-idf
os_branch?=master
#os_machine?=esp32
IDF_PATH=${os_dir}
export IDF_PATH

app_dir?=${top_dir}/port/${port}
sub_dirs+=${app_dir}
sub_dirs+=${top_dir}/apps/st_app/${port}
#TODO: try to build more gemeric code
#sub_dirs+=${top_dir}/apps

toolchain_url?=https://dl.espressif.com/dl/xtensa-esp32-elf-linux64-1.22.0-80-g6c4433a-5.2.0.tar.gz
toolchain_abi?=xtensa-esp32-elf
toolchain_dir?=${extra_dir}/${toolchain_abi}
toolchain_bin?=${toolchain_dir}/bin

CROSSCOMPIL?=${toolchain_bin}/${toolchain_abi}-
CC=${CROSSCOMPIL}gcc
export CC
PATH:=${toolchain_bin}:${PATH}
export PATH

prep_files+=${CC}

CFLAGS+=-Werror
export CFLAGS

${os_dir}:
	git clone --depth 1 --recursive -b ${os_branch} ${os_url} $@

${os_dir}/%: ${os_dir}
	ls $@

${toolchain_dir}:
	mkdir -p ${@D}
	cd ${@D} && curl -sL ${toolchain_url} | tar xz
	ls $@ 
	ls ${toolchain_bin}
	ls ${CC}
	-file ${CC}
	${CC} --version

${toolchain_dir}/%: ${toolchain_dir}
	ls $@

all: prep build

prep: ${prep_files} ${CC}
	${CC} --version

build/hello: ${os_dir}
	${MAKE} -C $</examples/get-started/hello_world/ all

build: ${sub_dirs} ${prep_files}
	for sub_dir in ${sub_dirs}; do ${MAKE} -C $${sub_dir} ; done


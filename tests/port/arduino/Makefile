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
	sync

top_rel_dir?=../../..
top_dir?=${CURDIR}/${top_rel_dir}
extra_dir?=${top_dir}/deps

app_dir?=${top_dir}/port/noop

os_dir?=.
os_url?=
os_branch?=.
os_machine?=mega256
configure_file?=

toolchain_abi?=avr
toolchain_dir?=/usr
toolchain_package?=gcc-avr
toolchain_bin?=${toolchain_dir}/bin

CROSSCOMPIL?=${toolchain_bin}/${toolchain_abi}-
CC=${CROSSCOMPIL}gcc
export CC
PATH:=${toolchain_bin}:${PATH}
export PATH

prep_files+=${CC}

prep_files+=${top_dir}/deps/tinycbor/LICENSE

${top_dir}/deps/tinycbor/%:
	${MAKE} -C "${top_dir}/tests" prep

${os_dir}/%: ${os_dir}
	ls "$@"

build: ${app_dir}
	${MAKE} -C "$<"

prep: ${prep_files}
	ls $^


toolchain/setup: ${CC}
	$< --version
	@echo "PATH=${PATH}"

toolchain/setup/debian:
	sudo apt-get install -y ${package}

all: toolchain/setup prep build
	sync

#! /usr/bin/make -f

topdir?=${CURDIR}/..
port?=linux

default: ${port}/all
	sync

DYNAMIC?=0
export DYNAMIC

SECURE?=0
export SECURE

TCP?=0
export TCP

prep_files+=${topdir}/deps/tinycbor/LICENSE
prep_files+=${topdir}/deps/mbedtls/LICENSE
prep_files+=${topdir}/deps/gtest/LICENSE

linux/%: ${prep_files}
	${MAKE} -C ${CURDIR}/../port/${port} ${@F}


tizenrt/%: ${prep_files}
	${MAKE} -C ${CURDIR}/port/${port} ${@F}


help: ${topdir}/README.rst
	cat $<
	@echo "# Usage: "
	@echo "# make all : to build port=${port}"

${prep_files}:
	git submodule init ${@D}
	git submodule sync ${@D}
	git submodule update ${@D}

test: ${port}/test

.PHONY: default help

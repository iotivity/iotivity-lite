#! /usr/bin/make -f

topdir?=${CURDIR}/..
port?=linux

default: rule/all
	sync

DYNAMIC?=0
export DYNAMIC

SECURE?=0
export SECURE

TCP?=0
export TCP

prep_files+=${topdir}/deps/tinycbor/LICENSE
prep_files+=${topdir}/deps/mbedtls/LICENSE

rule/%: ${prep_files}
	${MAKE} -C ${CURDIR}/../port/${port} ${@F}

help: ${topdir}/README.rst
	cat $<
	@echo "# Usage: "
	@echo "# make all : to build port=${port}"

${prep_files}: ${CURDIR}/prep-stamp.tmp
	@ls $@

${CURDIR}/prep-stamp.tmp:
	git submodule init
	git submodule sync
	git submodule update
	touch $@

test: rule/test

.PHONY: default help

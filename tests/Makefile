#! /usr/bin/make -f

topdir?=${CURDIR}/..
port?=linux

default: all
	sync

prep_files+=${topdir}/deps/tinycbor/LICENSE
prep_files+=${topdir}/deps/mbedtls/LICENSE

%: ${prep_files}
	${MAKE} -C ${CURDIR}/../port/${port} $@

help: ${topdir}/README.rst
	cat $<
	@echo "# Usage: "
	@echo "# make all : to build port=${port}"

${prep_files}: prep
	@ls $@

prep:
	git submodule init
	git submodule sync
	git submodule update

.PHONY: default help prep

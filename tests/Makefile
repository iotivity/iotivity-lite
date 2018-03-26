#! /usr/bin/make -f

port?=linux

default: all
	sync

prep_files+=deps/tinycbor/LICENSE deps/mbedtls/LICENSE

%: ${prep_files}
	${MAKE} -C ${CURDIR}/../port/${port} $@

help: README.rst
	cat $<
	@echo "# Usage: "
	@echo "# make all : to build port=${port}"

${prep_files}:
	git submodule init
	git submodule sync
	git submodule update

.PHONY: default help

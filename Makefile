port?=linux

.PHONY: default help README

default: help

help: README
	@cat $<
	@echo "make all : to build port=${port}"

%: port/${port}
	${MAKE} -C $< $@

.PHONY: default help README

default: all
	sync

%:
	${MAKE} -C ${CURDIR}/tests rule/$@

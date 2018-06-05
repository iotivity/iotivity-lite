CC = gcc
CFLAGS=-fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I./ -I../ -I../../ -I../../include/ -std=gnu99 -Wall -Wextra #-Wl,-Map,client.map
CFLAGS += -I./include
LIBS?= -lm -pthread -lrt

all: st_things

st_things:
	@mkdir -p $@_creds
	${CC} -o $@ st_ref_app.c  \
			lib/libst-app-framework.a ${CFLAGS} ${LIBS}
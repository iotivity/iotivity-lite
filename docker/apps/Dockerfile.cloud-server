FROM alpine:3.12 AS build
ARG BUILD_ARGS
RUN apk add --no-cache curl git build-base gcc linux-headers patch
COPY ./  /iotivity-lite/
RUN cd /iotivity-lite/ && git submodule update --recursive
RUN make -C /iotivity-lite/port/linux $BUILD_ARGS cloud_server

FROM alpine:3.12 AS service
RUN apk add --no-cache bash
COPY --from=build /iotivity-lite/port/linux/cloud_server /iotivity-lite/port/linux/service
COPY /docker/run.sh /usr/local/bin/run.sh
ENV NUM_DEVICES=1
ENTRYPOINT ["/usr/local/bin/run.sh"]
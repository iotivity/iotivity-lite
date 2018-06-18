#!/bin/echo docker build . -f
# -*- coding: utf-8 -*-
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

FROM debian:stable
MAINTAINER Philippe Coval (philippe.coval@osg.samsung.com)

ENV DEBIAN_FRONTEND noninteractive
ENV LC_ALL en_US.UTF-8
ENV LANG ${LC_ALL}

RUN echo "#log: Configuring locales" \
  && set -x \
  && apt-get update -y \
  && apt-get install -y locales \
  && echo "${LC_ALL} UTF-8" | tee /etc/locale.gen \
  && locale-gen ${LC_ALL} \
  && dpkg-reconfigure locales \
  && sync

RUN echo "#log: ${project}: Setup system" \
  && set -x \
  && apt-get update -y \
  && apt-get install -y \
  build-essential \
  curl \
  git \
  make \
  python \
\
  gawk \
  && apt-get clean \
  && sync

ENV project iotivity-constrained

ADD . /usr/local/src/${project}/${project}/
WORKDIR /usr/local/src/${project}/${project}/
RUN echo "#log: ${project}: Preparing sources" \
  && set -x \
  && sync

RUN echo "#log: ${project}: Building sources" \
  && set -x \
  && cd tests \
  && ls \
  &&  ./auto_build.sh tizenrt \
  && sync

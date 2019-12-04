#  #################################################################
# 
#  Created on Tue Mar 19 2019
# 
#  #################################################################
#  
#  Copyright (c) 2019 DEKRA Testing and Certification, S.A.U., All Rights Reserved.
#  
#  #################################################################
#  
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
# 
#         http://www.apache.org/licenses/LICENSE-2.0
# 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
# 
#  ###################################################################
# 
#	Linux: make OS=linux
#	Android: 
#		Set ANDROID_API and ANDROID_BASE in this makefile: make OS=android
# 		or invoke like this: make OS=android NDK_HOME=/opt/android-ndk ANDROID_API=23
#

JAVA_HOME ?= $(shell readlink -e "$$(dirname "$$(readlink -e "$$(which javac)")")"/..)
JAVAC = javac
JAVAH = javah
JAR = jar
SWIG = swig

# Java package name
PACKAGE_NAME = org.iotivity
PACKAGE_DIR = org/iotivity/

JAR_NAME = iotivity-lite.jar
JNI_SO_NAME = libiotivity-lite-jni.so

# Directories
IOTIVITY_LITE_JAVA_DIR = iotivity-lite-java/
IOTIVITY_LITE_JAVA_SRC_DIR = $(IOTIVITY_LITE_JAVA_DIR)src/
IOTIVITY_LITE_JAVA_JNI_DIR = $(IOTIVITY_LITE_JAVA_DIR)jni/
IOTIVITY_LITE_JAVA_LIBS_DIR = $(IOTIVITY_LITE_JAVA_DIR)libs/
IOTIVITY_LITE_JAVA_BIN_DIR = $(IOTIVITY_LITE_JAVA_DIR)bin/
JAVA_LANG_DIR = java_lang/
JAVA_LANG_OBJ_DIR =
CLIENT_SERVER_OBJ_DIR = $(PORT_OBJ_DIR)client_server/
CLOUD_OBJ_DIR =
OC_JAVA_DIR = oc_java/
SWIG_INTERFACES_DIR = swig_interfaces/

# SWIG
SWIG_CFLAG = 
HEADER_FILE = -I../ -I../include -I../port -I../util/ -I../deps/tinycbor/src/ -I../security -I../cloud

JNIFLAG = -fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-strict-overflow -Wno-unused-function
EXTRA_FLAG = -std=gnu99 -Wall -DOC_CLIENT -DOC_SERVER -DOC_IPV4 -DOC_DYNAMIC_ALLOCATION -DLONG_BIT=64
DTLSFLAGS=-I../deps/mbedtls/include -D__OC_RANDOM
LDFLAG += -lm

INSTALL_ANDROID_LIBS =

ifeq ($(DEBUG),1)
	EXTRA_FLAG += -DOC_DEBUG -g -O0
endif

ifeq ($(CLOUD),1)
	TCP=1
	EXTRA_FLAG += -DOC_CLOUD
	CLOUD_OBJ_DIR = $(PORT_OBJ_DIR)cloud/*.o
endif

ifneq ($(SECURE),0)
	EXTRA_FLAG += -DOC_SECURITY
endif

ifeq ($(IDD), 1)
	EXTRA_FLAG += -DOC_IDD_API
endif

ifneq ($(PKI),0)
	EXTRA_FLAG += -DOC_PKI
endif

ifeq ($(TCP),1)
	EXTRA_FLAG += -DOC_TCP
	SWIG_CFLAG += -DOC_TCP
endif

SRC = oc_api oc_buffer_settings oc_clock oc_cloud oc_collection oc_connectivity \
		oc_core_res oc_cred oc_endpoint oc_enums oc_introspection oc_obt oc_pki \
		oc_rep oc_session_events oc_storage oc_uuid

# Swig interfaces source
SWIG_INTERFACE_SRC = $(addsuffix .i, $(SRC))
JNI_SRC = $(addsuffix _wrap.c, $(SRC))
JNI_SRC += oc_iotivity_lite_jni.c

ifeq ($(OS),linux)
	EXTRA_HEADER_FILE = -I"$(JAVA_HOME)/include/" -I"$(JAVA_HOME)/include/linux/"
	PORT_OBJ_DIR = ../port/linux/obj/
	SWIG_CFLAG += -D__linux__
	EXTRA_FLAG += -fno-strict-aliasing
	HEADER_FILE += -I../port/linux
	LDFLAG += -lpthread -lrt
endif
ifeq ($(OS),android)
	EXTRA_HEADER_FILE = -I"$(ANDROID_BASE)/sysroot/usr/include/"
	PORT_OBJ_DIR = ../port/android/arm-linux-androideabi-obj/
	SWIG_CFLAG += -D__linux__
	HEADER_FILE += -I../port/android
	LDFLAG += -llog
	INSTALL_ANDROID_LIBS = install_android_libs
ifeq ($(ANDROID_API),)
	EXTRA_FLAG += -D__ANDROID_API__=23
else
	EXTRA_FLAG += -D__ANDROID_API__=$(ANDROID_API)
endif
endif

JAVA_LANG_OBJ_DIR += $(PORT_OBJ_DIR)swig/

all: clean build_swig build_jar build_jni_so $(INSTALL_ANDROID_LIBS)

.PHONY: clean

build_swig: $(SWIG_INTERFACE_SRC) copy_java

%.i:
	$(SWIG) -java -package $(PACKAGE_NAME) -outdir $(IOTIVITY_LITE_JAVA_SRC_DIR)$(PACKAGE_DIR) $(SWIG_CFLAG) $(HEADER_FILE) -o $(addsuffix _wrap.c, $(IOTIVITY_LITE_JAVA_JNI_DIR)$(basename $@)) $(SWIG_INTERFACES_DIR)$@

copy_java:
	cp $(JAVA_LANG_DIR)*.h $(IOTIVITY_LITE_JAVA_JNI_DIR)
	cp $(JAVA_LANG_DIR)*.c $(IOTIVITY_LITE_JAVA_JNI_DIR)
	cp $(OC_JAVA_DIR)*.java $(IOTIVITY_LITE_JAVA_SRC_DIR)$(PACKAGE_DIR)
	mkdir -p $(IOTIVITY_LITE_JAVA_SRC_DIR)$(PACKAGE_DIR)oc/
	cp $(OC_JAVA_DIR)oc/*.java $(IOTIVITY_LITE_JAVA_SRC_DIR)$(PACKAGE_DIR)oc/

build_jar: copy_java
	mkdir -p $(IOTIVITY_LITE_JAVA_BIN_DIR)
	$(JAVAC) -source 1.7 -target 1.7 -sourcepath $(IOTIVITY_LITE_JAVA_SRC_DIR) -d $(IOTIVITY_LITE_JAVA_BIN_DIR) $(IOTIVITY_LITE_JAVA_SRC_DIR)$(PACKAGE_DIR)*.java $(IOTIVITY_LITE_JAVA_SRC_DIR)$(PACKAGE_DIR)oc/*.java
	$(JAR) -cfv $(IOTIVITY_LITE_JAVA_LIBS_DIR)$(JAR_NAME) -C $(IOTIVITY_LITE_JAVA_BIN_DIR) .

build_jni_so: $(JNI_SRC)
	$(CC) -shared $(JAVA_LANG_OBJ_DIR)*.o $(PORT_OBJ_DIR)*.o $(CLIENT_SERVER_OBJ_DIR)*.o $(CLOUD_OBJ_DIR) $(LDFLAG) -o $(IOTIVITY_LITE_JAVA_LIBS_DIR)$(JNI_SO_NAME)

install_android_libs: build_swig build_jar build_jni_so
	# copy so and jar files to samples
	cp $(IOTIVITY_LITE_JAVA_LIBS_DIR)$(JNI_SO_NAME) apps/oc/android_simple_client/SimpleClient/app/src/main/jniLibs/armeabi/
	cp $(IOTIVITY_LITE_JAVA_LIBS_DIR)$(JAR_NAME) apps/oc/android_simple_client/SimpleClient/app/libs/
	cp $(IOTIVITY_LITE_JAVA_LIBS_DIR)$(JNI_SO_NAME) apps/oc/android_simple_server/SimpleServer/app/src/main/jniLibs/armeabi/
	cp $(IOTIVITY_LITE_JAVA_LIBS_DIR)$(JAR_NAME) apps/oc/android_simple_server/SimpleServer/app/libs/
	cp $(IOTIVITY_LITE_JAVA_LIBS_DIR)$(JNI_SO_NAME) apps/oc/android_multi_device_client/MultiDeviceClient/app/src/main/jniLibs/armeabi/
	cp $(IOTIVITY_LITE_JAVA_LIBS_DIR)$(JAR_NAME) apps/oc/android_multi_device_client/MultiDeviceClient/app/libs/
	cp $(IOTIVITY_LITE_JAVA_LIBS_DIR)$(JNI_SO_NAME) apps/oc/android_multi_device_server/MultiDeviceServer/app/src/main/jniLibs/armeabi/
	cp $(IOTIVITY_LITE_JAVA_LIBS_DIR)$(JAR_NAME) apps/oc/android_multi_device_server/MultiDeviceServer/app/libs/
	cp $(IOTIVITY_LITE_JAVA_LIBS_DIR)$(JNI_SO_NAME) apps/oc/android_on_boarding_tool/OnBoardingTool/app/src/main/jniLibs/armeabi/
	cp $(IOTIVITY_LITE_JAVA_LIBS_DIR)$(JAR_NAME) apps/oc/android_on_boarding_tool/OnBoardingTool/app/libs/

%_wrap.c:
	mkdir -p $(JAVA_LANG_OBJ_DIR)
	$(CC) -c -o $(JAVA_LANG_OBJ_DIR)$(addsuffix .o, $(basename $@)) $(IOTIVITY_LITE_JAVA_JNI_DIR)$@ $(JNIFLAG) $(EXTRA_HEADER_FILE) $(HEADER_FILE) $(EXTRA_FLAG) $(DTLSFLAGS)

oc_iotivity_lite_jni.c:
	mkdir -p $(JAVA_LANG_OBJ_DIR)
	$(CC) -c -o $(JAVA_LANG_OBJ_DIR)$(addsuffix .o, $(basename $@)) $(IOTIVITY_LITE_JAVA_JNI_DIR)$@ $(JNIFLAG) $(EXTRA_HEADER_FILE) $(HEADER_FILE) $(EXTRA_FLAG) $(DTLSFLAGS)

clean:
	rm -f $(IOTIVITY_LITE_JAVA_LIBS_DIR)$(JAR_NAME)
	rm -f $(IOTIVITY_LITE_JAVA_LIBS_DIR)$(JNI_SO_NAME)
	rm -f $(addsuffix *.c, $(IOTIVITY_LITE_JAVA_JNI_DIR))
	rm -f $(addsuffix *.h, $(IOTIVITY_LITE_JAVA_JNI_DIR))
	rm -f $(addsuffix *.java, $(IOTIVITY_LITE_JAVA_SRC_DIR)$(PACKAGE_DIR))
	rm -rf $(IOTIVITY_LITE_JAVA_SRC_DIR)$(PACKAGE_DIR)oc
	rm -rf $(IOTIVITY_LITE_JAVA_BIN_DIR)
	rm -rf $(JAVA_LANG_OBJ_DIR)
	# delete so and jar files copied to samples
	rm -f apps/android_simple_client/SimpleClient/app/src/main/jniLibs/armeabi/$(JNI_SO_NAME)
	rm -f apps/android_simple_client/SimpleClient/app/libs/$(JAR_NAME)
	rm -f apps/android_simple_server/SimpleServer/app/src/main/jniLibs/armeabi/$(JNI_SO_NAME)
	rm -f apps/android_simple_server/SimpleServer/app/libs/$(JAR_NAME)
	rm -f apps/android_on_boarding_tool/OnBoardingTool/app/src/main/jniLibs/armeabi/$(JNI_SO_NAME)
	rm -f apps/android_on_boarding_tool/OnBoardingTool/app/libs/$(JAR_NAME)
	rm -f apps/oc/android_simple_client/SimpleClient/app/src/main/jniLibs/armeabi/$(JNI_SO_NAME)
	rm -f apps/oc/android_simple_client/SimpleClient/app/libs/$(JAR_NAME)
	rm -f apps/oc/android_simple_server/SimpleServer/app/src/main/jniLibs/armeabi/$(JNI_SO_NAME)
	rm -f apps/oc/android_simple_server/SimpleServer/app/libs/$(JAR_NAME)
	rm -f apps/oc/android_multi_device_client/MultiDeviceClient/app/src/main/jniLibs/armeabi/$(JNI_SO_NAME)
	rm -f apps/oc/android_multi_device_client/MultiDeviceClient/app/libs/$(JAR_NAME)
	rm -f apps/oc/android_multi_device_server/MultiDeviceServer/app/src/main/jniLibs/armeabi/$(JNI_SO_NAME)
	rm -f apps/oc/android_multi_device_server/MultiDeviceServer/app/libs/$(JAR_NAME)
	rm -f apps/oc/android_on_boarding_tool/OnBoardingTool/app/src/main/jniLibs/armeabi/$(JNI_SO_NAME)
	rm -f apps/oc/android_on_boarding_tool/OnBoardingTool/app/libs/$(JAR_NAME)
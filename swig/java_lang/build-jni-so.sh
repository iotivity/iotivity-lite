#!/bin/bash

# remove existing .o files
rm -rf ./obj

# create .o files directory
mkdir ./obj

# compile swig generated C/C++ files
gcc -c -fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I"$JAVA_HOME/include/" -I"$JAVA_HOME/include/linux/" -I../.. -I../../include/ -I../../port/ -I../../port/linux/ -I../../util/ -I../../deps/tinycbor/src/ -Wall -Wextra -Werror -pedantic -D__OC_RANDOM -DOC_CLIENT -DOC_SERVER -DOC_IPV4 -DOC_DYNAMIC_ALLOCATION -DOC_DEBUG -DOC_SECURITY -g -O0 -Wno-unused-parameter -Wno-strict-aliasing -Wno-unused-function -Wno-sign-compare -Wno-address ../iotivity-lite-java/jni/oc_api_wrap.c -o ./obj/oc_api_wrap.o

gcc -c -fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I"$JAVA_HOME/include/" -I"$JAVA_HOME/include/linux/" -I../../ -I../../include -I../../port/linux -Wall -Wextra -Werror -pedantic -D__OC_RANDOM -DOC_CLIENT -DOC_SERVER -DOC_IPV4 -DOC_DYNAMIC_ALLOCATION -DOC_DEBUG -DOC_SECURITY -g -O0 -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function ../iotivity-lite-java/jni/oc_storage_wrap.c  -o ./obj/oc_storage_wrap.o

gcc -c -fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I"$JAVA_HOME/include/" -I"$JAVA_HOME/include/linux/" -I../../ -I../../include -I../../port/linux -Wall -Wextra -Werror -pedantic -D__OC_RANDOM -DOC_CLIENT -DOC_SERVER -DOC_IPV4 -DOC_DYNAMIC_ALLOCATION -DOC_DEBUG -DOC_SECURITY -g -O0 -Wno-unused-parameter -Wno-strict-aliasing ../iotivity-lite-java/jni/oc_clock_wrap.c  -o ./obj/oc_clock_wrap.o

gcc -c -fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I"$JAVA_HOME/include/" -I"$JAVA_HOME/include/linux/" -I../.. -I../../include/ -I../../port/ -I../../port/linux -Wall -Wextra -Werror -pedantic -D__OC_RANDOM -DOC_CLIENT -DOC_SERVER -DOC_IPV4 -DOC_DYNAMIC_ALLOCATION -DOC_DEBUG -DOC_SECURITY -g -O0 -Wno-unused-parameter -Wno-strict-aliasing -Wno-address -Wno-unused-function -Wno-unused-variable ../iotivity-lite-java/jni/oc_collection_wrap.c  -o ./obj/oc_collection_wrap.o

gcc -c -fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I"$JAVA_HOME/include/" -I"$JAVA_HOME/include/linux/" -I../.. -I../../include/ -I../../port/ -I../../port/linux/ -I../../util/ -I../../deps/tinycbor/src/ -Wall -Wextra -Werror -pedantic -D__OC_RANDOM -DOC_CLIENT -DOC_SERVER -DOC_IPV4 -DOC_DYNAMIC_ALLOCATION -DOC_DEBUG -DOC_SECURITY -g -O0 -Wno-unused-parameter -Wno-strict-aliasing -Wno-unused-function -Wno-sign-compare -Wno-address ../iotivity-lite-java/jni/oc_obt_wrap.c -o ./obj/oc_obt_wrap.o

gcc -c -fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I"$JAVA_HOME/include/" -I"$JAVA_HOME/include/linux/" -I../.. -I../../include/ -I../../port/ -I../../port/linux/ -I../../util/ -I../../deps/tinycbor/src/ -Wall -Wextra -Werror -pedantic -D__OC_RANDOM -DOC_CLIENT -DOC_SERVER -DOC_IPV4 -DOC_DYNAMIC_ALLOCATION -DOC_DEBUG -DOC_SECURITY -g -O0 -Wno-unused-parameter -Wno-strict-aliasing -Wno-unused-function -Wno-unused-variable -Wno-sign-compare -Wno-address ../iotivity-lite-java/jni/oc_endpoint_wrap.c -o ./obj/oc_endpoint_wrap.o

gcc -c -fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I"$JAVA_HOME/include/" -I"$JAVA_HOME/include/linux/" -I../.. -I../../include/ -I../../port/ -I../../port/linux/ -I../../util/ -I../../deps/tinycbor/src/ -Wall -Wextra -Werror -pedantic -D__OC_RANDOM -DOC_CLIENT -DOC_SERVER -DOC_IPV4 -DOC_DYNAMIC_ALLOCATION -DOC_DEBUG -DOC_SECURITY -g -O0 -Wno-unused-parameter -Wno-strict-aliasing -Wno-unused-function -Wno-unused-variable -Wno-sign-compare -Wno-address ../iotivity-lite-java/jni/oc_pki_wrap.c -o ./obj/oc_pki_wrap.o

gcc -c -fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I"$JAVA_HOME/include/" -I"$JAVA_HOME/include/linux/" -I../.. -I../../include/ -I../../port/ -I../../port/linux/ -I../../util/ -I../../deps/tinycbor/src/ -Wall -Wextra -Werror -pedantic -D__OC_RANDOM -DOC_CLIENT -DOC_SERVER -DOC_IPV4 -DOC_DYNAMIC_ALLOCATION -DOC_DEBUG -DOC_SECURITY -g -O0 -Wno-unused-parameter -Wno-strict-aliasing -Wno-unused-function -Wno-unused-variable -Wno-sign-compare -Wno-address ../iotivity-lite-java/jni/oc_rep_wrap.c -o ./obj/oc_rep_wrap.o

gcc -c -fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I"$JAVA_HOME/include/" -I"$JAVA_HOME/include/linux/" -I../.. -I../../include/ -I../../port/ -I../../port/linux/ -I../../util/ -I../../deps/tinycbor/src/ -Wall -Wextra -Werror -pedantic -D__OC_RANDOM -DOC_CLIENT -DOC_SERVER -DOC_IPV4 -DOC_DYNAMIC_ALLOCATION -DOC_DEBUG -DOC_SECURITY -g -O0 -Wno-unused-parameter -Wno-strict-aliasing -Wno-unused-function -Wno-sign-compare -Wno-address -Wno-unused-variable ../iotivity-lite-java/jni/oc_uuid_wrap.c -o ./obj/oc_uuid_wrap.o

gcc -c -fPIC -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -ffreestanding -Os -fno-stack-protector -ffunction-sections -fdata-sections -fno-reorder-functions -fno-defer-pop -fno-strict-overflow -I"$JAVA_HOME/include/" -I"$JAVA_HOME/include/linux/" -I../.. -I../../include/ -I../../port/ -I../../port/linux/ -I../../util/ -I../../deps/tinycbor/src/ -Wall -Wextra -Werror -pedantic -D__OC_RANDOM -DOC_CLIENT -DOC_SERVER -DOC_IPV4 -DOC_DYNAMIC_ALLOCATION -DOC_DEBUG -DOC_SECURITY -g -O0 -Wno-unused-parameter -Wno-strict-aliasing -Wno-unused-function -Wno-sign-compare -Wno-address -Wno-unused-variable ../iotivity-lite-java/jni/oc_core_res_wrap.c -o ./obj/oc_core_res_wrap.o

# create shared library
gcc -shared ./obj/*.o ../../port/linux/obj/*.o ../../port/linux/obj/client_server/*.o  -lm -lpthread -lrt -o libiotivity-lite-jni.so

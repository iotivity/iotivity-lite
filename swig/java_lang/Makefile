SWIG_INTERFACES_DIR = ../swig_interfaces
SWIG_C_OUT_DIR = ../iotivity-lite-java/jni
SWIG_JAVA_OUT_DIR = ../iotivity-lite-java/src/org/iotivity/

SWIG_INTERFACES = oc_obt.i oc_uuid.i oc_collection.i oc_endpoint.i oc_pki.i \
oc_rep.i oc_api.i oc_clock.i oc_storage.i oc_acl.i

WRAPFILES = oc_api_wrap.c oc_collection_wrap.c oc_pki_wrap.c oc_storage_wrap.c \
oc_clock_wrap.c oc_endpoint_wrap.c oc_obt_wrap.c oc_rep_wrap.c oc_uuid_wrap.c

#WRAPFILE = $(SWIG_INTERFACES:.i=_wrap.c)

all: ${addprefix $(SWIG_C_OUT_DIR)/, $(WRAPFILES)}

$(SWIG_C_OUT_DIR)/%_wrap.c : $(SWIG_INTERFACES_DIR)/%.i
	swig -java -package org.iotivity -outdir $(SWIG_JAVA_OUT_DIR) -D__linux__ -I../.. -I../../port/linux/ -I../../include/ -I../../security/ -o $(SWIG_C_OUT_DIR)/$*_wrap.c $(SWIG_INTERFACES_DIR)/$*.i

.PHONY: clean
clean:
	rm -f ${addprefix $(SWIG_C_OUT_DIR)/, $(WRAPFILES)}
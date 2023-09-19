/* File oc_obt.i */
%module OCUuidUtil
%include "stdint.i"
%include "typemaps.i"
%include "iotivity.swg"

%pragma(java) jniclasscode=%{
  static {
    try {
        System.loadLibrary("iotivity-lite-jni");
    } catch (UnsatisfiedLinkError e) {
      System.err.println("Native code library failed to load. \n" + e);
      System.exit(1);
    }
  }
%}

%{
#include "oc_uuid.h"
%}

#define OC_UUID_LEN (37)
#define OC_UUID_ID_SIZE (16)

%typemap(jstype) uint8_t id[OC_UUID_ID_SIZE] "byte[]"
%typemap(jtype) uint8_t id[OC_UUID_ID_SIZE] "byte[]"
%typemap(jni) uint8_t id[OC_UUID_ID_SIZE] "jbyteArray"
%typemap(javaout) uint8_t id[OC_UUID_ID_SIZE] {
  return $jnicall;
}
%typemap(out) uint8_t id[OC_UUID_ID_SIZE] {
  if($1 != NULL) {
    $result = JCALL1(NewByteArray, jenv, (jsize)OC_UUID_ID_SIZE);
    JCALL4(SetByteArrayRegion, jenv, $result, 0, (jsize)OC_UUID_ID_SIZE, (const jbyte *)$1);
  } else {
    $result = NULL;
  }
}
%typemap(javain) uint8_t id[OC_UUID_ID_SIZE] "$javainput"
%typemap(in) uint8_t id[OC_UUID_ID_SIZE] (uint8_t temp[OC_UUID_ID_SIZE]) {
  jbyte *jid = JCALL2(GetByteArrayElements, jenv, $input, 0);
  //jsize jid_size = JCALL1(GetArrayLength, jenv, $input);
  // TODO if jid_size != OC_UUID_ID_SIZE throw exception
  memcpy(temp, jid, OC_UUID_ID_SIZE);
  $1 = temp;
  JCALL3(ReleaseByteArrayElements, jenv, $input, jid, 0);
}

%rename(OCUuid) oc_uuid_t;
%typemap(javacode) oc_uuid_t %{
  public boolean equals(Object obj) {
    boolean equal = false;
    if (obj instanceof OCUuid) {
        String objectUuid = OCUuidUtil.uuidToString((OCUuid)obj);
        String thisUuid = OCUuidUtil.uuidToString(this);
        equal = objectUuid.equals(thisUuid);
    }
    return equal;
  }
  public int hashCode() {
     return java.util.UUID.fromString(OCUuidUtil.uuidToString(this)).hashCode();
  }
%}


%ignore oc_str_to_uuid;
%rename(stringToUuid) jni_str_to_uuid;
%newobject jni_str_to_uuid;
%inline %{
oc_uuid_t * jni_str_to_uuid(const char *str)
{
  oc_uuid_t *value = (oc_uuid_t *)malloc(sizeof(oc_uuid_t));
  oc_str_to_uuid(str, value);
  return value;
}
%}

%ignore oc_uuid_to_str;
%rename(uuidToString) jni_uuid_to_str;
%newobject jni_uuid_to_str;
%inline %{
char * jni_uuid_to_str(const oc_uuid_t *uuid)
{
  char *retValue = (char *)malloc(sizeof(char) * OC_UUID_LEN);
  oc_uuid_to_str(uuid, retValue, OC_UUID_LEN);
  return retValue;
}
%}


%ignore oc_gen_uuid;
%rename(generateUuid) jni_gen_uuid;
%newobject jni_gen_uuid;
%inline %{
oc_uuid_t * jni_gen_uuid(void)
{
  oc_uuid_t *value = (oc_uuid_t *)malloc(sizeof(oc_uuid_t));
  oc_gen_uuid(value);
  return value;
}
%}

#define OC_API
#define OC_NONNULL(...)
%include oc_uuid.h

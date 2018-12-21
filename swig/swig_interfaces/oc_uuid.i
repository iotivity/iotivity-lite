/* File oc_obt.i */
%module OCUuidUtil
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

%typemap(jstype) uint8_t id[16] "byte[]"
%typemap(jtype) uint8_t id[16] "byte[]"
%typemap(jni) uint8_t id[16] "jbyteArray"
%typemap(javaout) uint8_t id[16] {
  return $jnicall;
}
%typemap(out) uint8_t id[16] {
  if($1 != NULL) {
    $result = JCALL1(NewByteArray, jenv, (jsize)16);
    JCALL4(SetByteArrayRegion, jenv, $result, 0, (jsize)16, (const jbyte *)$1);
  } else {
    $result = NULL;
  }
}
%typemap(javain) uint8_t id[16] "$javainput"
%typemap(in) uint8_t id[16] (uint8_t temp[16]) {
  jbyte *jid = JCALL2(GetByteArrayElements, jenv, $input, 0);
  //jsize jid_size = JCALL1(GetArrayLength, jenv, $input);
  // TODO if jid_size != 16 throw exception
  memcpy(temp, jid, 16);
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
oc_uuid_t * jni_gen_uuid()
{
  oc_uuid_t *value = (oc_uuid_t *)malloc(sizeof(oc_uuid_t));
  oc_gen_uuid(value);
  return value;
}
%}

%include oc_uuid.h
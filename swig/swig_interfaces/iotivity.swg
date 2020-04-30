/* -----------------------------------------------------------------------------
 * iotivity.swg
 *
 * iotivity-lite typemaps
 * ----------------------------------------------------------------------------- */

/*********************************************************************
 * collection of code need across the project
 *********************************************************************/
%{
#include "oc_iotivity_lite_jni.h"
#include "oc_collection.h"
#include "port/oc_log.h"
%}


/*********************************************************************
 * change enums being used as bitmaps to integers for Java enums do
 * not work as bitmaps in Java due to language constraints.
 ********************************************************************/

%typemap(in)      oc_interface_mask_t "$1 = (oc_interface_mask_t)$input;"
%typemap(out)     oc_interface_mask_t "$result = (jint)$1;"
%typemap(jni)     oc_interface_mask_t "jint";
%typemap(jtype)   oc_interface_mask_t "int";
%typemap(jstype)  oc_interface_mask_t "int";
%typemap(javain)  oc_interface_mask_t "$javainput"
%typemap(javaout) oc_interface_mask_t { return $jnicall; }

%typemap(in)      oc_resource_properties_t "$1 = (oc_resource_properties_t)$input;"
%typemap(out)     oc_resource_properties_t "$result = (jint)$1;"
%typemap(jni)     oc_resource_properties_t "jint";
%typemap(jtype)   oc_resource_properties_t "int";
%typemap(jstype)  oc_resource_properties_t "int";
%typemap(javain)  oc_resource_properties_t "$javainput"
%typemap(javaout) oc_resource_properties_t { return $jnicall; }

%typemap(in)      transport_flags "$1 = (transport_flags)$input;"
%typemap(out)     transport_flags "$result = (jint)$1;"
%typemap(jni)     enum transport_flags "jint";
%typemap(jtype)   enum transport_flags "int";
%typemap(jstype)  enum transport_flags "int";
%typemap(javain)  enum transport_flags "$javainput"
%typemap(javaout) enum transport_flags { return $jnicall; }

%typemap(in)      oc_ace_permissions_t "$1 = (oc_ace_permissions_t)$input;"
%typemap(out)     oc_ace_permissions_t "$result = (jint)$1;"
%typemap(jni)     oc_ace_permissions_t "jint";
%typemap(jtype)   oc_ace_permissions_t "int";
%typemap(jstype)  oc_ace_permissions_t "int";
%typemap(javain)  oc_ace_permissions_t "$javainput"
%typemap(javaout) oc_ace_permissions_t { return $jnicall; }

%typemap(in)      oc_sp_types_t "$1 = (oc_sp_types_t)$input;"
%typemap(out)     oc_sp_types_t "$result = (jint)$1;"
%typemap(jni)     oc_sp_types_t "jint";
%typemap(jtype)   oc_sp_types_t "int";
%typemap(jstype)  oc_sp_types_t "int";
%typemap(javain)  oc_sp_types_t "$javainput"
%typemap(javaout) oc_sp_types_t { return $jnicall; }

%typemap(in)      oc_cloud_status_t "$1 = (oc_sp_types_t)$input;"
%typemap(out)     oc_cloud_status_t "$result = (jint)$1;"
%typemap(jni)     oc_cloud_status_t "jint";
%typemap(jtype)   oc_cloud_status_t "int";
%typemap(jstype)  oc_cloud_status_t "int";
%typemap(javain)  oc_cloud_status_t "$javainput"
%typemap(javaout) oc_cloud_status_t { return $jnicall; }
/********************************************************************
 * oc_string_t input param - treat as String
 ********************************************************************/
%typemap(javain) oc_string_t "$javainput"
%typemap(javaout) oc_string_t {
    return $jnicall;
  }
%typemap(jni)    oc_string_t "jstring"
%typemap(jtype)  oc_string_t "String"
%typemap(jstype) oc_string_t "String"

%typemap(in, noblock=1) oc_string_t (const char *temp) {
  temp = 0;
  $1.ptr = 0;
  if ($input) {
    temp = JCALL2(GetStringUTFChars, jenv, $input, 0);
    oc_new_string(&$1, temp, JCALL1(GetStringUTFLength, jenv, $input));
    if (!$1.ptr) {
      return $null;
    }
  }
}

// TODO find out if this is used anywhere in the generated code this may be wrong
%typemap(directorout, noblock=1) oc_string_t {
  $1 = 0;
  if ($input) {
    $result = ($1_ltype)JCALL2(GetStringUTFChars, jenv, oc_string($input), 0);
    if (!$result) return $null;
  }
}

// TODO not sure about these next few items  most likely should be using oc_new_string, and oc_free_string
%typemap(directorin, descriptor="Ljava/lang/String;", noblock=1) oc_string_t {
  $input = 0;
  if ($1) {
    $input = JCALL1(NewStringUTF, jenv, (const char *)$1);
    if (!$input) return $null;
  }
  Swig::LocalRefGuard $1_refguard(jenv, $input);
}

// TODO double check if argout is used anywhere in the generated code.
%typemap(argout) oc_string_t ""

%typemap(freearg, noblock=1) oc_string_t {
  if ($1.ptr) {
    JCALL2(ReleaseStringUTFChars, jenv, $input, temp$argnum);
  }
}

%typemap(out, noblock=1) oc_string_t {
  if ($1.ptr) {
    $result = JCALL1(NewStringUTF, jenv, (const char *)oc_string($1));
  }
}

%typemap(javadirectorin) oc_string_t "$jniinput"
%typemap(javadirectorout) oc_string_t "$javacall"

/********************************************************************
 * oc_string* as INPUT parameter
 ********************************************************************/
%typemap(javain) oc_string_t *INPUT "$javainput"
%typemap(javaout) oc_string_t *INPUT{
    return $jnicall;
  }
%typemap(jni)    oc_string_t *INPUT "jstring"
%typemap(jtype)  oc_string_t *INPUT "String"
%typemap(jstype) oc_string_t *INPUT "String"

%typemap(in, noblock=1) oc_string_t *INPUT (const char *temp, oc_string_t temp_oc_string) {
  temp = 0;
  $1 = &temp_oc_string;
  if ($input) {
    temp = JCALL2(GetStringUTFChars, jenv, $input, 0);
    oc_new_string($1, temp, JCALL1(GetStringUTFLength, jenv, $input));
    if ($1 && !$1->ptr) {
      oc_free_string($1);
      return $null;
    }
  }
}

// TODO find out if this is used anywhere in the generated code this may be wrong
%typemap(directorout, noblock=1) oc_string_t *INPUT{
  $1 = 0;
  if ($input) {
    $result = ($1_ltype)JCALL2(GetStringUTFChars, jenv, oc_string($input), 0);
    if (!$result) return $null;
  }
}

// TODO not sure about these next few items  most likely should be using oc_new_string, and oc_free_string
%typemap(directorin, descriptor="Ljava/lang/String;", noblock=1) oc_string_t *INPUT{
  $input = 0;
  if ($1) {
    $input = JCALL1(NewStringUTF, jenv, (const char *)$1);
    if (!$input) return $null;
  }
  Swig::LocalRefGuard $1_refguard(jenv, $input);
}

// TODO double check if argout is used anywhere in the generated code.
%typemap(argout) oc_string_t *INPUT""

%typemap(freearg, noblock=1) oc_string_t *INPUT{
  if ($1 && $1->ptr) {
    JCALL2(ReleaseStringUTFChars, jenv, $input, temp$argnum);
    oc_free_string($1);
  }
}

%typemap(out, noblock=1) oc_string_t *INPUT{
  if (&$1) {
    $result = JCALL1(NewStringUTF, jenv, (const char *)oc_string($1));
  }
}

%typemap(javadirectorin) oc_string_t *INPUT"$jniinput"
%typemap(javadirectorout) oc_string_t *INPUT"$javacall"

/********************************************************************
 * oc_string* as OUTPUT parameter
 ********************************************************************/
%typemap(jni) oc_string_t *OUTPUT "jobjectArray"
%typemap(jtype) oc_string_t *OUTPUT "String[]"
%typemap(jstype) oc_string_t *OUTPUT "String[]"
%typemap(javain) oc_string_t *OUTPUT "$javainput"
%typemap(javadirectorin) oc_string_t *OUTPUT "$javainput"
%typemap(javadirectorout) oc_string_t *OUTPUT "$javacall"

%typemap(in) oc_string_t *OUTPUT ($*1_ltype temp) {
  if (!$input) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "array null");
    return $null;
  }
  if (JCALL1(GetArrayLength, jenv, $input) == 0) {
    SWIG_JavaThrowException(jenv, SWIG_JavaIndexOutOfBoundsException, "Array must contain at least 1 element");
    return $null;
  }
  temp.ptr = (void *)0;
  $1 = &temp;
}

%typemap(freearg) oc_string_t *OUTPUT ""


/* TODO figureout a way to free the string that is returned in the array
%typemap(freearg) oc_string_t *OUTPUT {
  if ($1 && $1->ptr) {
    jstring jvalue = (jstring)JCALL2(GetObjectArrayElement, jenv, $input, 0);
    JCALL2(ReleaseStringUTFChars, jenv, jvalue, oc_string(temp$argnum));
  }
}
*/

%typemap(argout) oc_string_t *OUTPUT {
  jstring jvalue = JCALL1(NewStringUTF, jenv, oc_string(temp$argnum));
  JCALL3(SetObjectArrayElement, jenv, $input, 0, jvalue);
}

/********************************************************************
 * oc_string_array_t
 ********************************************************************/
%typemap(jni) oc_string_array_t "jobjectArray"
%typemap(jni) oc_string_array_t "jobjectArray"
%typemap(jtype) oc_string_array_t "String[]"
%typemap(jstype) oc_string_array_t "String[]"
%typemap(in) oc_string_array_t (jint jsize) {
  int i = 0;
  if ($input) {
    jsize = JCALL1(GetArrayLength, jenv, $input);
    oc_new_string_array(&$1, jsize);
    for (i = 0; i<jsize; i++) {
      jstring j_string = (jstring)JCALL2(GetObjectArrayElement, jenv, $input, i);
      const char *c_string = JCALL2(GetStringUTFChars, jenv, j_string, 0);
      oc_string_array_add_item($1, c_string);
      JCALL2(ReleaseStringUTFChars, jenv, j_string, c_string);
      JCALL1(DeleteLocalRef, jenv, j_string);
    }
  } else {
    $1.ptr = 0;
    $1.size = 0;
    jsize = 0;
  }
}

%typemap(freearg) oc_string_array_t ""

%typemap(out) oc_string_array_t {
  if ($1.ptr) {
    int i;
    jsize len=0;
    jstring temp_string;
    const jclass clazz = JCALL1(FindClass, jenv, "java/lang/String");
    len = (jsize)oc_string_array_get_allocated_size($1);
    $result = JCALL3(NewObjectArray, jenv, len, clazz, NULL);
    /* exception checking omitted */

    for (i=0; i<len; i++) {
      //temp_string = JCALL1(NewStringUTF, jenv, *$1++);
      temp_string = JCALL1(NewStringUTF, jenv, oc_string_array_get_item($1, i));
      JCALL3(SetObjectArrayElement, jenv, $result, i, temp_string);
      JCALL1(DeleteLocalRef, jenv, temp_string);
    }
  }
}

%typemap(javain) oc_string_array_t "$javainput"
%typemap(javaout) oc_string_array_t {
    return $jnicall;
}


/********************************************************************
 * map unsigned char*. size_t to byte[]
 * use the swig apply key word to use.
 * example:
 * %apply (const unsigned char * BYTE, size_t LENGTH)   { (const unsigned char *value, size_t length) };
 ********************************************************************/
%typemap(in)     (const unsigned char * BYTE, size_t LENGTH) {
/* Functions from jni.h */
$1 = (unsigned char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
$2 = (size_t) JCALL1(GetArrayLength,       jenv, $input);
}
%typemap(jni)    (const unsigned char * BYTE, size_t LENGTH) "jbyteArray"
%typemap(jtype)  (const unsigned char * BYTE, size_t LENGTH) "byte[]"
%typemap(jstype) (const unsigned char * BYTE, size_t LENGTH) "byte[]"
%typemap(javain) (const unsigned char * BYTE, size_t LENGTH) "$javainput"

/********************************************************************
 * Code and typemaps for mapping the oc_discovery_all_handler_t to the
 * java OCDiscoveryAllHandler
 ********************************************************************/
%typemap(jni)    oc_discovery_all_handler_t handler "jobject";
%typemap(jtype)  oc_discovery_all_handler_t handler "OCDiscoveryAllHandler";
%typemap(jstype) oc_discovery_all_handler_t handler "OCDiscoveryAllHandler";
%typemap(javain) oc_discovery_all_handler_t handler "$javainput";
%typemap(in,numinputs=1) (oc_discovery_all_handler_t handler, jni_callback_data *jcb) {
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  // TODO figure out the lifetime of the oc_discovery_all_handler_t
  user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
  jni_list_add(user_data);
  $1 = jni_oc_discovery_all_handler_callback;
  $2 = user_data;
}
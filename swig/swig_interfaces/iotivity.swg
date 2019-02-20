/* -----------------------------------------------------------------------------
 * iotivity.swg
 *
 * iotivity-lite typemaps
 * ----------------------------------------------------------------------------- */

/*********************************************************************
 * collection of code need across the project
 *********************************************************************/
%{
#include "oc_collection.h"
#include "port/oc_log.h"

/*
 * JNI function calls require different calling conventions for C and C++. These JCALL macros are used so
 * that the same typemaps can be used for generating code for both C and C++. These macros are originaly from
 * the SWIG javahead.swg. They placed here because the SWIG preprocessor does not expand macros that are
 * within the SWIG header code insertion blocks.
 */
#ifdef __cplusplus
#   define JCALL0(func, jenv) jenv->func()
#   define JCALL1(func, jenv, ar1) jenv->func(ar1)
#   define JCALL2(func, jenv, ar1, ar2) jenv->func(ar1, ar2)
#   define JCALL3(func, jenv, ar1, ar2, ar3) jenv->func(ar1, ar2, ar3)
#   define JCALL4(func, jenv, ar1, ar2, ar3, ar4) jenv->func(ar1, ar2, ar3, ar4)
#   define JCALL5(func, jenv, ar1, ar2, ar3, ar4, ar5) jenv->func(ar1, ar2, ar3, ar4, ar5)
#   define JCALL6(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6) jenv->func(ar1, ar2, ar3, ar4, ar5, ar6)
#   define JCALL7(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7) jenv->func(ar1, ar2, ar3, ar4, ar5, ar6, ar7)
#   define JCALL8(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8) jenv->func(ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8)
#   define JCALL9(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8, ar9) jenv->func(ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8, ar9)
#else
#   define JCALL0(func, jenv) (*jenv)->func(jenv)
#   define JCALL1(func, jenv, ar1) (*jenv)->func(jenv, ar1)
#   define JCALL2(func, jenv, ar1, ar2) (*jenv)->func(jenv, ar1, ar2)
#   define JCALL3(func, jenv, ar1, ar2, ar3) (*jenv)->func(jenv, ar1, ar2, ar3)
#   define JCALL4(func, jenv, ar1, ar2, ar3, ar4) (*jenv)->func(jenv, ar1, ar2, ar3, ar4)
#   define JCALL5(func, jenv, ar1, ar2, ar3, ar4, ar5) (*jenv)->func(jenv, ar1, ar2, ar3, ar4, ar5)
#   define JCALL6(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6) (*jenv)->func(jenv, ar1, ar2, ar3, ar4, ar5, ar6)
#   define JCALL7(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7) (*jenv)->func(jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7)
#   define JCALL8(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8) (*jenv)->func(jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8)
#   define JCALL9(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8, ar9) (*jenv)->func(jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8, ar9)
#endif

/*
 * This struct used to hold information needed for java callbacks.
 * When registering a callback handler from java the `JNIEnv`
 * and the java callback handler object must be stored so they
 * can later be used when the callback comes from C this is
 * the `jcb_obj`.
 *
 * If the function used to register the callback also accepts
 * user_data in the form of a void* the `jni_callback_data`
 * can be passed up to the C layer so it can be used in the
 * callback function.
 *
 * The `juser_data` is used to hold a java object that is passed
 * in when registering a callback handler. This value can then be
 * passed back upto the java callback class. Serving the same
 * function as the C void *user_data pointer.
 */
typedef struct jni_callback_data_s {
  struct jni_callback_data_s *next;
  JNIEnv *jenv;
  jobject jcb_obj;
} jni_callback_data;

/*
 * Container used to hold all `jni_callback_data` that is
 * allocated dynamically. This can be used to find the
 * memory allocated for the `jni_callback_data` if the callback
 * is removed or unregistered. This can all so be used to clean
 * up the allocated memory when shutting down the stack.
 */
OC_LIST(jni_callbacks);

#define JNI_CURRENT_VERSION JNI_VERSION_1_6

static JavaVM *jvm;

static JNIEnv* GetJNIEnv(jint* getEnvResult)
{
    JNIEnv *env = NULL;
    *getEnvResult = JCALL2(GetEnv, jvm, (void**)&env, JNI_CURRENT_VERSION);
    switch (*getEnvResult)
    {
        case JNI_OK:
            return env;
        case JNI_EDETACHED:
#    ifdef __ANDROID__
            if(JCALL2(AttachCurrentThread, jvm, &env, NULL) < 0)
#    else
            if(JCALL2(AttachCurrentThread, jvm, (void**)&env, NULL) < 0)
#    endif
            {
                OC_DBG("Failed to get the environment");
                return NULL;
            }
            else
            {
                return env;
            }
        case JNI_EVERSION:
            OC_DBG("JNI version not supported");
            break;
        default:
            OC_DBG("Failed to get the environment");
            return NULL;
    }
    return NULL;
}

static void ReleaseJNIEnv(jint getEnvResult) {
    if (JNI_EDETACHED == getEnvResult) {
        JCALL0(DetachCurrentThread, jvm);
    }
}
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
  if (&$1) {
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

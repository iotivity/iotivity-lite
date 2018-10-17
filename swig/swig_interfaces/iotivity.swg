/* -----------------------------------------------------------------------------
 * iotivity.swg
 *
 * iotivity-lite typemaps
 * ----------------------------------------------------------------------------- */


%typemap(jni)     oc_interface_mask_t "jint";
%typemap(jtype)   oc_interface_mask_t "int";
%typemap(jstype)  oc_interface_mask_t "int";
%typemap(javain)  oc_interface_mask_t "$javainput"
%typemap(javaout) oc_interface_mask_t { return $jnicall; }

%typemap(jni)     oc_resource_properties_t "jint";
%typemap(jtype)   oc_resource_properties_t "int";
%typemap(jstype)  oc_resource_properties_t "int";
%typemap(javain)  oc_resource_properties_t "$javainput"
%typemap(javaout) oc_resource_properties_t { return $jnicall; }

%typemap(jni)     enum transport_flags "jint";
%typemap(jtype)   enum transport_flags "int";
%typemap(jstype)  enum transport_flags "int";
%typemap(javain)  enum transport_flags "$javainput"
%typemap(javaout) enum transport_flags { return $jnicall; }

/********************************************************************
 * oc_string_t input param - treat as String                        *
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
 * oc_string* as INPUT parameter                                    *
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
 * oc_string* as OUTPUT parameter                                   *
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
/* -----------------------------------------------------------------------------
 * iotivity.swg
 *
 * iotivity-lite typemaps
 * ----------------------------------------------------------------------------- */

/*
%typemap(jni)     oc_interface_mask_t "jint";
%typemap(jtype)   oc_interface_mask_t "int";
%typemap(jstype)  oc_interface_mask_t "int";
%typemap (javain) oc_interface_mask_t "$javainput"
%typemap(javaout) oc_interface_mask_t { return $jnicall; }
*/

/* oc_string_t - treat as String */
%typemap(javain) oc_string_t "$javainput"
%typemap(javaout) oc_string_t {
    return $jnicall;
  }
%typemap(jni)    oc_string_t "jstring"
%typemap(jtype)  oc_string_t "String"
%typemap(jstype) oc_string_t "String"

%typemap(in, noblock=1) oc_string_t (const char* temp) {
  temp = 0;
  $1.ptr = 0;
  if ($input) {
    temp = JCALL2(GetStringUTFChars, jenv, $input, 0);
    oc_new_string(&$1, temp, JCALL1(GetStringUTFLength, jenv, $input));
    if (!$1.ptr) return $null;
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

// TODO double check it argout is used anywhere in the generated code.
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
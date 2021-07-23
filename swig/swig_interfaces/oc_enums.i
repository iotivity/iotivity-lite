/* File oc_enums.i */
%module OCEnumUtil

%include "enums.swg"
%javaconst(1);

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
#include "oc_enums.h"
%}

%rename(OCEnum) oc_enum_t;
%rename("%(strip:[OC_ENUM_])s", %isenumitem) "";
%rename(OCPositionDescription) oc_pos_description_t;
%rename("%(strip:[OC_POS_])s", %isenumitem) "";

%rename(enumToString) oc_enum_to_str;
%rename(positionDescriptionToString) oc_enum_pos_desc_to_str;

%include "oc_enums.h"

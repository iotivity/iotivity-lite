/* ****************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/
#include <string.h>

#include "oc_helpers.h"
#include "es_common.h"

 
// Helper to convert Enum to String (char*) value (by searching it in the lookup table)
#define lookup_enum_tostr(val, lut, ret) \
{ \
    ret = NULL; \
    const size_t n = sizeof(lut) / sizeof(lut[0]); \
    for (size_t i = 0; i < n; ++i) \
    { \
        if (lut[i].val_enum == val) \
        { \
            ret = lut[i].val_str; \
            break; \
        } \
    } \
}

// Helper to convert String (char*) to Enum value (by searching it in the lookup table)
#define lookup_str_toenum(val_in, lut, val_out, result) \
{ \
    result = false; \
    const size_t n = sizeof(lut) / sizeof(lut[0]); \
    for (size_t i = 0; i < n; ++i) \
    { \
        if (strcmp(lut[i].val_str, val_in) == 0) \
        { \
            val_out = lut[i].val_enum; \
            result = true; \
            break; \
        } \
    } \
}

static const struct
{
    wifi_mode val_enum;
    char *val_str;
} WIFIMODE_CONVERT_LOOKUP[] =
{
    { WIFI_11A, "A" },
    { WIFI_11B, "B" },
    { WIFI_11G, "G" },
    { WIFI_11N, "N" },
    { WIFI_11AC, "AC" },
};

static const struct
{
    wifi_freq val_enum;
    char *val_str;
} WIFIFREQ_CONVERT_LOOKUP[] =
{
    { WIFI_24G, "2.4G" },
    { WIFI_5G, "5G"}
};

static const struct
{
    wifi_authtype val_enum;
    char *val_str;
} WIFIAUTHTYPE_CONVERT_LOOKUP[] =
{
    { NONE_AUTH, "None" },
    { WEP, "WEP"},
    { WPA_PSK, "WPA_PSK" },
    { WPA2_PSK, "WPA2_PSK" },
};

static const struct
{
    wifi_enctype val_enum;
    char *val_str;
} WIFIENCTYPE_CONVERT_LOOKUP[] =
{
    { NONE_ENC, "None" },
    { WEP_64, "WEP_64" },
    { WEP_128, "WEP_128" },
    { TKIP, "TKIP" },
    { AES, "AES" },
    { TKIP_AES, "TKIP_AES" },
};

const char* 
wifi_mode_enum_tostring(wifi_mode val)
{
    char *ret = NULL;
    lookup_enum_tostr(val, WIFIMODE_CONVERT_LOOKUP, ret);
    return ret;
}

const char* 
wifi_freq_enum_tostring(wifi_freq val)
{
    char *ret = NULL;
    lookup_enum_tostr(val, WIFIFREQ_CONVERT_LOOKUP, ret);
    return ret;
}

const char* 
wifi_authtype_enum_tostring(wifi_authtype val)
{
    char *ret = NULL;
    lookup_enum_tostr(val, WIFIAUTHTYPE_CONVERT_LOOKUP, ret);
    return ret;
}

bool 
wifi_authtype_string_toenum(const char *val, wifi_authtype *val_out)
{
    bool result = false;
    lookup_str_toenum(val, WIFIAUTHTYPE_CONVERT_LOOKUP, (*val_out), result);
    return result;
}

const char* 
wifi_enctype_enum_tostring(wifi_enctype val)
{
    char *ret = NULL;
    lookup_enum_tostr(val, WIFIENCTYPE_CONVERT_LOOKUP, ret);
    return ret;
}

//******************************************************************
//
// Copyright 2015 Samsung Electronics All Rights Reserved.
//
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


#include "samsung/sc_easysetup.h"
#include "string.h"
#include "oc_log.h"
#include "stdio.h"
#include "oc_helpers.h"

#include "resourcehandler.h"

/**
 * @var SC_ENROLLEE_TAG
 * @brief Logging tag for module name.
 */
#define SC_ENROLLEE_TAG "ES_SC_ENROLLEE"

#define MAX_REP_ARRAY_DEPTH 3
#define	PRId64			"lld"		/* int64_t */

#define SC_RSRVD_ES_VENDOR_NETCONNECTION_STATE  x.com.samsung.ncs
#define SC_RSRVD_ES_VENDOR_DISCOVERY_CHANNEL    x.com.samsung.chn
#define SC_RSRVD_ES_VENDOR_DEVICE_TYPE          x.com.samsung.dt
#define SC_RSRVD_ES_VENDOR_DEVICE_SUBTYPE       x.com.samsung.sdt
#define SC_RSRVD_ES_VENDOR_LOCATION             x.com.samsung.location
#define SC_RSRVD_ES_VENDOR_CLIENTID             x.com.samsung.clientid
#define SC_RSRVD_ES_VENDOR_REGISTER_MOBILE_DEV  x.com.samsung.rmd
#define SC_RSRVD_ES_VENDOR_REGISTER_SET_DEV     x.com.samsung.rsd
#define SC_RSRVD_ES_VENDOR_NETWORK_PROV_INFO    x.com.samsung.npi
#define SC_RSRVD_ES_VENDOR_ACCOUNT              x.com.samsung.account
#define SC_RSRVD_ES_VENDOR_SSO_LIST            x.com.samsung.ssolist
#define SC_RSRVD_ES_VENDOR_AAC                  x.com.samsung.aac
#define SC_RSRVD_ES_VENDOR_TNC_HEADER           x.com.samsung.tcheader
#define SC_RSRVD_ES_VENDOR_TNC_VERSION          x.com.samsung.tcversion
#define SC_RSRVD_ES_VENDOR_TNC_RESULT           x.com.samsung.tcresult
#define SC_RSRVD_ES_VENDOR_TNC_STATUS           x.com.samsung.tcstatus
#define SC_RSRVD_ES_VENDOR_REFRESH_TOKEN        x.com.samsung.refreshtoken
#define SC_RSRVD_ES_VENDOR_UID                  x.com.samsung.uid
#define SC_RSRVD_ES_VENDOR_BSSID                x.com.samsung.bssid
#define SC_RSRVD_ES_VENDOR_PNP_PIN              x.com.samsung.pnppin
#define SC_RSRVD_ES_VENDOR_MODEL_NUMBER         x.com.samsung.modelnumber
#define SC_RSRVD_ES_VENDOR_LANGUAGE             x.com.samsung.language
#define SC_RSRVD_ES_VENDOR_COUNTRY              x.com.samsung.country
#define SC_RSRVD_ES_VENDOR_GPSLOCATION          x.com.samsung.gpslocation
#define SC_RSRVD_ES_VENDOR_UTC_DATE_TIME        x.com.samsung.datetime
#define SC_RSRVD_ES_VENDOR_REGIONAL_DATE_TIME   x.com.samsung.regionaldatetime
#define SC_RSRVD_ES_VENDOR_ES_PROTOCOL_VERSION  x.com.samsung.espv

easy_setup_resource g_ESEasySetupResource;
wifi_conf_resource g_ESWiFiConfResource;
coap_cloud_conf_resource g_ESCoapCloudConfResource;
dev_conf_resource g_ESDevConfResource;

sc_properties g_SCProperties;

static void read_account_data(oc_rep_t* payload,void** userdata);
static void read_tnc_data(oc_rep_t* payload,void** userdata);
static void write_tnc_data(oc_rep_t* payload, char* resourceType);
static void write_wifi_data(oc_rep_t* payload, char* resourceType);

#define stringify(s) #s

#define set_custom_property_str(object, key, value) oc_rep_set_text_string(object, key, value)
#define set_custom_property_int(object, key, value) oc_rep_set_int(object, key, value)

static bool payload_get_prop_string(oc_rep_t* payload, const char* name, char** value)
{
    OC_DBG("payload_get_prop_string IN");
    oc_rep_t *rep = payload;

    while(rep != NULL) {
	if(strcmp(oc_string(rep->name), name) == 0 && rep->type == OC_REP_STRING) {
		*value = strdup((char *)(oc_string(rep->value.string)));
		return true;
	}

	rep = rep->next;
    }

    OC_DBG("payload_get_prop_string OUT");
    return false;
}

static bool payload_get_prop_int(oc_rep_t* payload, const char* name, int64_t* value)
{
    oc_rep_t *rep = payload;
    while(rep != NULL) {
	if(strcmp(oc_string(rep->name), name) == 0 && rep->type == OC_REP_INT) { 
		*value = rep->value.integer;
		return true;
	}
	rep = rep->next;
   }
   return false;
}

static bool payload_get_prop_string_array(oc_rep_t* payload, const char* name,
        char*** array, int  *dimensions)
{
	oc_rep_t *rep = payload;
	while(rep != NULL) {
		if(strcmp(oc_string(rep->name), name) == 0 && rep->type == OC_REP_STRING_ARRAY) {
			oc_array_t rep_array=rep->value.array;
			int array_size = (int)oc_string_array_get_allocated_size(rep_array);
			*array = (char**)malloc(array_size * sizeof(char*));
			if (!*array)
			{
				return false;
			}
			*dimensions = array_size;
			for(int i = 0; i < array_size; ++i)
			{
				(*array)[i] = strdup(oc_string_array_get_item(rep->value.array, i));
			}

			return true;
		}
		rep = rep->next;
	}
	return false;
}

es_result_e set_sc_properties(const sc_properties *prop)
{
    OC_DBG("SetSCProperties IN");
    if(prop != NULL)
    {
        memcpy(&g_SCProperties, prop, sizeof(sc_properties));
        OC_ERR("SetSCProperties OUT");
        return ES_OK;
    }
    OC_DBG("SetSCProperties OUT");
    return ES_ERROR;
}

static void read_account_data(oc_rep_t* payload,void** userdata)
{
    OC_DBG("ReadAccountData IN");

    char* account = NULL;

    if(payload_get_prop_string(payload, STR_SC_RSRVD_ES_VENDOR_ACCOUNT, &account))
    	{
        if(*userdata == NULL)
        {
            *userdata = (void*)malloc(sizeof(sc_dev_conf_properties));
            if( *userdata == NULL )
            {
                OC_DBG("OICMalloc for SCDevConfProperties is failed");
                free(account);
                return;
            }
        }

        sc_dev_conf_properties *pDevConfProp = (sc_dev_conf_properties*)(*userdata);
        strncpy(pDevConfProp->account, account, MAXLEN_STRING);
        strncpy(g_SCProperties.account, account, MAXLEN_STRING);

        OC_DBG("[User specific property] %s : %s",STR_SC_RSRVD_ES_VENDOR_ACCOUNT, pDevConfProp->account);

        free(account);
    	}
    OC_DBG("ReadAccountData OUT");

}

es_result_e set_sc_tnc_info(sc_tnc_info *tncInfo)
{
    if(tncInfo == NULL)
    {
        return ES_ERROR;
    }
    g_SCProperties.tncInfo = *tncInfo;
    return ES_OK;
}

es_result_e set_sc_tnc_status(int status)
{
    g_SCProperties.tncStatus = status;
    return ES_OK;
}

es_result_e set_sc_net_connection_state(NETCONNECTION_STATE netConnectionState)
{
    OC_DBG( "SetSCNetConnectionState IN");

    OC_DBG( "SetSCNetConnectionState: %d", netConnectionState);
    g_SCProperties.netConnectionState = netConnectionState;

    if(0 == oc_notify_observers(g_ESEasySetupResource.handle))
    {
        OC_DBG("provResource doesn't have any observers.");
    }

    OC_DBG("SetSCNetConnectionState OUT");
    return ES_OK;
}

static void read_tnc_data(oc_rep_t* payload,void** userdata)
{
    OC_DBG("ReadTnCdata IN");

    char* tncResult = NULL;

    if (payload_get_prop_string(payload,  STR_SC_RSRVD_ES_VENDOR_TNC_RESULT, &tncResult))
    {
        if(*userdata == NULL)
        {
            *userdata = (void*)malloc(sizeof(sc_coap_cloud_server_conf_properties));
            if( *userdata == NULL )
            {
                OC_ERR("OICMalloc for sc_coap_cloud_server_conf_properties is failed");
                return ;
            }
        }

        sc_coap_cloud_server_conf_properties *pProp = (sc_coap_cloud_server_conf_properties*)(*userdata);
        strncpy(pProp->tncResult, tncResult, MAXLEN_STRING);
        strncpy(g_SCProperties.tncResult, tncResult, MAXLEN_STRING);

        OC_DBG("[User specific property] %s : %s",STR_SC_RSRVD_ES_VENDOR_TNC_RESULT, pProp->tncResult);
    }

   OC_DBG("ReadTnCdata OUT");
}

void write_tnc_data(oc_rep_t* payload, char* resourceType)
{
    OC_DBG("WriteTnCdata IN");
    (void)resourceType;
    (void)payload;

    if(resourceType == NULL)
    {
        OC_ERR("resourceType is NULL");
        OC_ERR("WriteTnCdata OUT");
        return;
    }
    if(strstr(resourceType, OC_RSRVD_ES_RES_TYPE_EASYSETUP))
    {
        set_custom_property_int(root, SC_RSRVD_ES_VENDOR_TNC_STATUS, g_SCProperties.tncStatus);
    }
    else if(strstr(resourceType, OC_RSRVD_ES_RES_TYPE_DEVCONF))
    {
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_TNC_HEADER,
                g_SCProperties.tncInfo.header);
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_TNC_VERSION,
                g_SCProperties.tncInfo.version);
    }
    else if(strstr(resourceType, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF))
    {
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_TNC_RESULT,
                g_SCProperties.tncResult);
    }
    OC_DBG("WriteTnCdata OUT");
}

void write_wifi_data(oc_rep_t* payload, char* resourceType)
{
    OC_DBG("WriteWifiData IN");
    (void)resourceType;
    (void)payload;

    if(resourceType == NULL)
    {
        OC_DBG("Invalid Params resourceType is NULL");
        OC_DBG("WriteWifiData OUT");
        return;
    }

    if(strstr(resourceType, OC_RSRVD_ES_RES_TYPE_WIFICONF))
    {
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_BSSID,
                g_SCProperties.bssid);
    }
    OC_DBG("WriteWifiData OUT");
}

es_result_e set_register_set_device(const char *regSetDevice)
{
    if(regSetDevice != NULL)
    {
        strncpy(g_SCProperties.regSetDev, regSetDevice, sizeof(g_SCProperties.regSetDev));
        return ES_OK;
    }
    return ES_ERROR;
}

es_result_e set_network_prov_info(const char *nwProvInfo)
{
    if(nwProvInfo != NULL)
    {
        strncpy(g_SCProperties.nwProvInfo, nwProvInfo, sizeof(g_SCProperties.nwProvInfo));
        return ES_OK;
    }
    return ES_ERROR;
}

es_result_e set_sc_pnp_pin(const char *pnp)
{
    if(pnp != NULL)
    {
        strncpy(g_SCProperties.pnpPin, pnp, sizeof(g_SCProperties.pnpPin));
        return ES_OK;
    }
    return ES_ERROR;
}

es_result_e set_es_version_info(const char *esProtocolVersion)
{
    if(esProtocolVersion != NULL)
    {
        strncpy(g_SCProperties.esProtocolVersion, esProtocolVersion, sizeof(g_SCProperties.esProtocolVersion));
        return ES_OK;
    }
    return ES_ERROR;
}

void ReadUserdataCb(oc_rep_t* payload, char* resourceType, void** userdata)
{
    OC_DBG("ReadUserdataCb IN");
    (void)resourceType;
    (void)payload;
    (void)userdata;

        if(strstr(resourceType, OC_RSRVD_ES_RES_TYPE_WIFICONF))
        {
            int64_t channel = -1;
            char *bssid = NULL;
            if (payload_get_prop_int(payload,  STR_SC_RSRVD_ES_VENDOR_DISCOVERY_CHANNEL, &channel))
            {
                if(*userdata == NULL)
                {
                    *userdata = (void*)malloc(sizeof(sc_wifi_conf_properties));
                    if( *userdata == NULL )
                    {
                        OC_ERR("OICMalloc for SCWiFiConfProperties is failed");
                        return ;
                    }
                    memset(*userdata, 0, sizeof(sc_wifi_conf_properties));
                }
                OC_DBG("[User specific property] %s : [%" PRId64 "]",STR_SC_RSRVD_ES_VENDOR_DISCOVERY_CHANNEL, channel);
                ((sc_wifi_conf_properties*)(*userdata))->discoveryChannel = (int) channel;
                g_SCProperties.discoveryChannel = channel;
            }
            if (payload_get_prop_string(payload,  STR_SC_RSRVD_ES_VENDOR_BSSID, &bssid))
            {
                if(*userdata == NULL)
                {
                    *userdata = (void*) malloc(sizeof(sc_wifi_conf_properties));
                    if( *userdata == NULL )
                    {
                        OC_ERR("OICMalloc for SCWiFiConfProperties is failed");
                        return ;
                    }
                    memset(*userdata, 0, sizeof(sc_wifi_conf_properties));
                }
                if (*userdata != NULL)
                {
                   OC_DBG("[User specific property] %s : %s",STR_SC_RSRVD_ES_VENDOR_BSSID, bssid);
                    sc_wifi_conf_properties* pWifiConfProp = (sc_wifi_conf_properties*)(*userdata);
                    strncpy(pWifiConfProp->bssid, bssid, sizeof(pWifiConfProp->bssid));
                    strncpy(g_SCProperties.bssid, bssid, sizeof(g_SCProperties.bssid));
                    free(bssid);
                }
            }
        }
        else if(strstr(resourceType, OC_RSRVD_ES_RES_TYPE_DEVCONF))
        {
            if(*userdata == NULL)
            {
                *userdata = (void*)malloc(sizeof(sc_dev_conf_properties));
                if( *userdata == NULL )
                {
                    OC_ERR("OICMalloc for SCDevConfProperties is failed");
                    return ;
                }
                memset(*userdata, 0, sizeof(sc_dev_conf_properties));
            }

            sc_dev_conf_properties *pDevConfProp = (sc_dev_conf_properties*)(*userdata);

            char**locationList = NULL;
            int dimensions;
            if(payload_get_prop_string_array(payload, STR_SC_RSRVD_ES_VENDOR_LOCATION, &locationList, &dimensions))
            {
                for(int idx = 0; idx < dimensions; idx++)
                {
                    strncpy(pDevConfProp->location[idx], locationList[idx], strlen(locationList[idx])+1);
                    strncpy(g_SCProperties.location[idx], locationList[idx], strlen(locationList[idx])+1);

                    OC_DBG("[User specific property] %s : %s",STR_SC_RSRVD_ES_VENDOR_LOCATION, pDevConfProp->location[idx]);
                }

                ((sc_dev_conf_properties*)(*userdata))->numLocation = (int)dimensions;
                g_SCProperties.numLocation = (int)dimensions;
            }

            read_account_data(payload,userdata);

            char *regMobileDev = NULL;
            if (payload_get_prop_string(payload,  STR_SC_RSRVD_ES_VENDOR_REGISTER_MOBILE_DEV, &regMobileDev))
            {
                strncpy(pDevConfProp->regMobileDev, regMobileDev, strlen(regMobileDev)+1);
                strncpy(g_SCProperties.regMobileDev, regMobileDev, strlen(regMobileDev)+1);
                OC_DBG("pDevConfProp.regMobileDev %s", g_SCProperties.regMobileDev);
            }

            char *country = NULL;
            if (payload_get_prop_string(payload,  STR_SC_RSRVD_ES_VENDOR_COUNTRY, &country))
            {
            OC_DBG("pDevConfProp.country %s", country);
                strncpy(pDevConfProp->country, country, strlen(country)+1);
                strncpy(g_SCProperties.country, country, strlen(country)+1);
                OC_DBG("pDevConfProp.country %s", g_SCProperties.country);
            }

            char *language = NULL;
            if (payload_get_prop_string(payload,  STR_SC_RSRVD_ES_VENDOR_LANGUAGE, &language))
            {
                strncpy(pDevConfProp->language, language, strlen(language)+1);
                strncpy(g_SCProperties.language, language, strlen(language)+1);
                OC_DBG("pDevConfProp.language %s", g_SCProperties.language);
            }

            char *gpsLocation = NULL;
            if (payload_get_prop_string(payload,  STR_SC_RSRVD_ES_VENDOR_GPSLOCATION, &gpsLocation))
            {
                strncpy(pDevConfProp->gpsLocation, gpsLocation, strlen(gpsLocation)+1);
                strncpy(g_SCProperties.gpsLocation, gpsLocation, strlen(gpsLocation)+1);
                OC_DBG( "pDevConfProp.gpsLocation %s", g_SCProperties.gpsLocation);
            }

            char *utcDateTime = NULL;
            if (payload_get_prop_string(payload,  STR_SC_RSRVD_ES_VENDOR_UTC_DATE_TIME, &utcDateTime))
            {
                strncpy(pDevConfProp->utcDateTime, utcDateTime, strlen(utcDateTime)+1);
                strncpy(g_SCProperties.utcDateTime, utcDateTime, strlen(utcDateTime)+1);
                OC_DBG("pDevConfProp.utcDateTime %s", g_SCProperties.utcDateTime);
            }

            char *regionalDateTime = NULL;
            if (payload_get_prop_string(payload,  STR_SC_RSRVD_ES_VENDOR_REGIONAL_DATE_TIME, &regionalDateTime))
            {
                strncpy(pDevConfProp->regionalDateTime, regionalDateTime, strlen(regionalDateTime)+1);
                strncpy(g_SCProperties.regionalDateTime, regionalDateTime, strlen(regionalDateTime)+1);
                OC_DBG("pDevConfProp.regionalDateTime %s", g_SCProperties.regionalDateTime);
            }

            char *ssoList = NULL;
            if (payload_get_prop_string(payload,  STR_SC_RSRVD_ES_VENDOR_SSO_LIST, &ssoList))
            {
                strncpy(pDevConfProp->ssoList, ssoList, strlen(ssoList)+1);
                strncpy(g_SCProperties.ssoList, ssoList, strlen(ssoList)+1);
                OC_DBG("pDevConfProp.ssoList %s", g_SCProperties.ssoList);
            }
        }
        else if(strstr(resourceType, OC_RSRVD_ES_RES_TYPE_COAPCLOUDCONF))
        {
            char* clientID = NULL;
            if(payload_get_prop_string(payload,  STR_SC_RSRVD_ES_VENDOR_CLIENTID, &clientID))
            {
                if(*userdata == NULL)
                {
                    *userdata = (void*)malloc(sizeof(sc_coap_cloud_server_conf_properties));
                    if( *userdata == NULL )
                    {
                        OC_ERR("OICMalloc for sc_coap_cloud_server_conf_properties is failed");
                        return ;
                    }
                    memset(*userdata, 0, sizeof(sc_coap_cloud_server_conf_properties));
                }

                sc_coap_cloud_server_conf_properties *pCloudProp =
                                                    (sc_coap_cloud_server_conf_properties*)(*userdata);

                strncpy(pCloudProp->clientID, clientID, strlen(clientID)+1);
                strncpy(g_SCProperties.clientID, clientID, strlen(clientID)+1);

               OC_DBG("[User specific property] %s : %s", STR_SC_RSRVD_ES_VENDOR_CLIENTID, pCloudProp->clientID);
            }

            //SC_RSRVD_ES_VENDOR_AAC
            char *aac = NULL;
            if (payload_get_prop_string(payload,  STR_SC_RSRVD_ES_VENDOR_AAC, &aac))
            {
                if(*userdata == NULL)
                {
                    *userdata = (void*)malloc(sizeof(sc_coap_cloud_server_conf_properties));
                    if( *userdata == NULL )
                    {
                        OC_ERR("OICMalloc for sc_coap_cloud_server_conf_properties is failed");
                        return ;
                    }
                    memset(*userdata, 0, sizeof(sc_coap_cloud_server_conf_properties));
                }

                if (*userdata != NULL)
                {
                    sc_coap_cloud_server_conf_properties *pCloudProp =
                                                    (sc_coap_cloud_server_conf_properties*) (*userdata);
                    pCloudProp->aac[0] = '\0';

                    strncpy(pCloudProp->aac, aac, MAXLEN_STRING);
                    strncpy(g_SCProperties.aac, aac, MAXLEN_STRING);
                    free(aac);

                    OC_DBG("[User specific property] %s : %s", STR_SC_RSRVD_ES_VENDOR_AAC, pCloudProp->aac);
                }
            }

            //SC_RSRVD_ES_VENDOR_UID
            char *uid = NULL;
            if (payload_get_prop_string(payload,  STR_SC_RSRVD_ES_VENDOR_UID, &uid))
            {
                if(*userdata == NULL)
                {
                    *userdata = (void*)malloc(sizeof(sc_coap_cloud_server_conf_properties));
                    if( *userdata == NULL )
                    {
                        OC_ERR("OICMalloc for sc_coap_cloud_server_conf_properties is failed");
                        return ;
                    }
                    memset(*userdata, 0, sizeof(sc_coap_cloud_server_conf_properties));
                }

                if (*userdata != NULL)
                {
                    sc_coap_cloud_server_conf_properties *pCloudProp =
                                                    (sc_coap_cloud_server_conf_properties*) (*userdata);
                    pCloudProp->uid[0] = '\0';

                    strncpy(pCloudProp->uid, uid, MAXLEN_STRING);
                    strncpy(g_SCProperties.uid, uid, MAXLEN_STRING);
                    free(uid);

                   OC_DBG("[User specific property] %s : %s",STR_SC_RSRVD_ES_VENDOR_UID, pCloudProp->uid);
                }
            }

            //SC_RSRVD_ES_VENDOR_REFRESH_TOKEN
            char *refreshToken = NULL;
            if (payload_get_prop_string(payload,  STR_SC_RSRVD_ES_VENDOR_REFRESH_TOKEN, &refreshToken))
            {
                if(*userdata == NULL)
                {
                    *userdata = (void*)malloc(sizeof(sc_coap_cloud_server_conf_properties));
                    if( *userdata == NULL )
                    {
                        OC_ERR("OICMalloc for sc_coap_cloud_server_conf_properties is failed");
                        return ;
                    }
                    memset(*userdata, 0, sizeof(sc_coap_cloud_server_conf_properties));
                }

                if (*userdata != NULL)
                {
                    sc_coap_cloud_server_conf_properties *pCloudProp =
                                                    (sc_coap_cloud_server_conf_properties*) (*userdata);
                    pCloudProp->refreshToken[0] = '\0';

                    strncpy(pCloudProp->refreshToken, refreshToken, MAXLEN_STRING);
                    strncpy(g_SCProperties.refreshToken, refreshToken, MAXLEN_STRING);
                    free(refreshToken);

                    OC_DBG("[User specific property] %s : %s",STR_SC_RSRVD_ES_VENDOR_REFRESH_TOKEN, pCloudProp->refreshToken);
                }
            }

            read_tnc_data(payload,userdata);
        }

    OC_DBG("ReadUserdataCb OUT");
}

void WriteUserdataCb(oc_rep_t* payload, char* resourceType)
{
    OC_DBG("WriteUserdataCb easy setup sc IN");
    (void)resourceType;
    (void)payload;


    if(strstr(resourceType, OC_RSRVD_ES_RES_TYPE_EASYSETUP))
    {
    OC_DBG("WriteUserdataCb OC_RSRVD_ES_RES_TYPE_EASYSETUP IN");
        set_custom_property_int(root, SC_RSRVD_ES_VENDOR_NETCONNECTION_STATE, (int) g_SCProperties.netConnectionState);
    }

    if(strstr(resourceType, OC_RSRVD_ES_RES_TYPE_DEVCONF))
    {
#ifndef __TIZENRT__
	  OC_DBG("WriteUserdataCb OC_RSRVD_ES_RES_TYPE_DEVCONF IN");
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_DEVICE_TYPE, g_SCProperties.deviceType);
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_DEVICE_SUBTYPE, g_SCProperties.deviceSubType);
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_REGISTER_SET_DEV, g_SCProperties.regSetDev);
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_REGISTER_MOBILE_DEV, g_SCProperties.regMobileDev);
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_NETWORK_PROV_INFO, g_SCProperties.nwProvInfo);
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_SSO_LIST, g_SCProperties.ssoList);
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_PNP_PIN, g_SCProperties.pnpPin);
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_MODEL_NUMBER, g_SCProperties.modelNumber);
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_COUNTRY, g_SCProperties.country);
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_LANGUAGE, g_SCProperties.language);
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_GPSLOCATION, g_SCProperties.gpsLocation);
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_UTC_DATE_TIME, g_SCProperties.utcDateTime);
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_REGIONAL_DATE_TIME, g_SCProperties.regionalDateTime);
        set_custom_property_str(root, SC_RSRVD_ES_VENDOR_ES_PROTOCOL_VERSION, g_SCProperties.esProtocolVersion);
#else
        if(g_SCProperties.deviceType != NULL)
        {
            set_custom_property_str(root, SC_RSRVD_ES_VENDOR_DEVICE_TYPE, g_SCProperties.deviceType);
        }
        if(g_SCProperties.deviceSubType != NULL)
        {
            set_custom_property_str(root, SC_RSRVD_ES_VENDOR_DEVICE_SUBTYPE, g_SCProperties.deviceSubType);
        }
        if(g_SCProperties.regSetDev != NULL)
        {
            set_custom_property_str(root, SC_RSRVD_ES_VENDOR_REGISTER_SET_DEV, g_SCProperties.regSetDev);
        }
        if(g_SCProperties.regMobileDev != NULL)
        {
            set_custom_property_str(root, SC_RSRVD_ES_VENDOR_REGISTER_MOBILE_DEV, g_SCProperties.regMobileDev);
        }
        if(g_SCProperties.nwProvInfo!= NULL)
        {
            set_custom_property_str(root, SC_RSRVD_ES_VENDOR_NETWORK_PROV_INFO, g_SCProperties.nwProvInfo);
        }
        if(g_SCProperties.ssoList!= NULL)
        {
            set_custom_property_str(root, SC_RSRVD_ES_VENDOR_SSO_LIST, g_SCProperties.ssoList);
        }
        if(g_SCProperties.pnpPin != NULL)
        {
           set_custom_property_str(root, SC_RSRVD_ES_VENDOR_PNP_PIN, g_SCProperties.pnpPin);
        }
        if(g_SCProperties.modelNumber != NULL)
        {
           set_custom_property_str(root, SC_RSRVD_ES_VENDOR_MODEL_NUMBER, g_SCProperties.modelNumber);
        }
        if(g_SCProperties.country != NULL)
        {
           set_custom_property_str(root, SC_RSRVD_ES_VENDOR_COUNTRY, g_SCProperties.country);
        }
        if(g_SCProperties.language != NULL)
        {
           set_custom_property_str(root, SC_RSRVD_ES_VENDOR_LANGUAGE, g_SCProperties.language);
        }
        if(g_SCProperties.gpsLocation != NULL)
        {
           set_custom_property_str(root, SC_RSRVD_ES_VENDOR_GPSLOCATION, g_SCProperties.gpsLocation);
        }
        if(g_SCProperties.esProtocolVersion != NULL)
        {
            set_custom_property_str(root, SC_RSRVD_ES_VENDOR_ES_PROTOCOL_VERSION, g_SCProperties.esProtocolVersion);
        }*/
#endif
    }

    write_tnc_data(payload, resourceType);
    write_wifi_data(payload, resourceType);

   OC_DBG("WriteUserdataCb OUT");
}

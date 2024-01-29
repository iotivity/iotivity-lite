/****************************************************************************
 *
 * Copyright 2023 ETRI All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * Created on: Nov 17, 2023,
 *        Author: Joo-Chul Kevin Lee (rune@etri.re.kr)
 *
 *
 ****************************************************************************/

#include "MatterTranslator.h"
#include "bridge_interface.h"
#include "matter_client.h"

using namespace ::std;

Json::Value ResourceToClusterMapper::jsonRoot;                  ///< json root object to store translation results
Json::Value ResourceFromClusterMapper::jsonRoot;                ///< json root object to store translation results
Json::StreamWriterBuilder ResourceToClusterMapper::jsonWriter;  ///< to make singleline json string

std::string MatterTranslator::mOcfSpecVersion;              ///< OCF spec version
std::string MatterTranslator::mOcfDmVersion;                ///< OCF Data model version

std::map<std::set<DeviceTypeId>, std::string> MatterTranslator::mMatterDeviceTypeName;        ///< dict of { Matter DeviceTypeId, Matter DeviceTypeName }
std::map<ClusterId, std::string> MatterTranslator::mMatterClusterIdName;                      ///< dict of { Matter ClusterId, Matter ClusterName }
std::map<std::set<std::string, std::less<>>, std::string> MatterTranslator::mOcfDeviceName;   ///< dict of { OCF Device Type, OCF Device Name }
std::map<std::string, std::string, std::less<>> MatterTranslator::mOcfResourceName;           ///< dict of { OCF Resoruce Type, OCF Resource Name }

/*
 * Matter Node list which keeps Matter Nodes corresponding to each OCF VOD
 */
std::map<size_t, std::pair<NodeId, EndpointId>> MatterTranslator::mMatterNodesByDeviceindex;  ///< mapping : OCF Device Index -> Matter Endpoint
std::map<NodeId, std::shared_ptr<MatterNode>> MatterTranslator::mMatterNodesByNodeid;         ///< mapping : Matter NodeID -> Matter Node

/*
 * Matter Translators for each direction
 */
std::map<std::set<std::string, std::less<>>, DeviceToEndpointMapper> MatterTranslator::mOcfToMatter;       ///< OCF -> Matter translator (DeviceType => EP DeviceTypeId)
std::map<std::set<DeviceTypeId>, DeviceFromEndpointMapper> MatterTranslator::mOcfFromMatter;  ///< OCF <- Matter translator (DeviceType <= EP DeviceTypeId)


/*
 * @brief iotivity-lite Retrieve callback for VOD
 * @param request RETRIEVE request from stack
 * @param iface_mask Request interface mask
 * @param user_data Extra user data
 */
void VODResourceGetHandler(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data);

/*
 * @brief iotivity-lite Update callback for VOD
 * @param request UPDATE request from stack
 * @param iface_mask Request interface mask
 * @param user_data Extra user data
 */
void VODResourcePostHandler(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data);

/*
 * @brief Clear all VODs mapped to all Matter EPs
 */
void ResetVODs();


void DeviceToEndpointMapper::Print()
{
  std::cout << "==> mDeviceId: " ;
  for (auto i: mDeviceTypeId) {
    std::cout << i << " ";
  }

  std::cout << std::endl;

  for (auto i: mMapper) {
    std::cout << "  ResourceType: " << i.first << std::endl;
    i.second.Print();
  }
}


void ResourceToClusterMapper::Print()
{
  std::cout << "    ==> mClusterName: " << mClusterName << std::endl;
  for (const auto & i: mMapper) {
    std::cout << "      Property Name: " << i.first << std::endl;
    i.second->Print();
  }
}

void PropertyToAttributeMapper::Print()
{
  for (const auto & i: mMapper) {
    std::cout << "      PropertyTranslationMode: " << (int)i.first << std::endl;
    for (auto j: i.second) {
      std::cout << "        index: " << j.first << " Attr/Com ID: " << j.second << std::endl;
    }
  }
}


void DeviceFromEndpointMapper::Print()
{
  std::cout << "==> mDeviceType: " ;
  for (const auto & i: mDeviceType) {
    std::cout << i << " ";
  }

  std::cout << std::endl;

  for (auto i: mMapper) {
    std::cout << "  ClusterId: " << i.first << std::endl;
    i.second.Print();
  }
}


void ResourceFromClusterMapper::Print()
{
  std::cout << "    ==> mResourceType: " << mResourceType << std::endl;
  for (const auto & i: mMapper) {
    std::cout << "      AttributeId: " << i.first << std::endl;
    i.second->Print();
  }
}


void PropertyFromAttributeMapper::Print()
{
  std::cout << "      ==> mPropertyName: " << mPropertyName << std::endl;
}


void MatterTranslator::Init(const string & ocfSpecVersion, const string & ocfDmVersion)
{
  mOcfSpecVersion = ocfSpecVersion;
  mOcfDmVersion = ocfDmVersion;

  /* make json object into single line string */
  ResourceToClusterMapper::JsonWriter()["indentation"] = "";

  mMatterNodesByDeviceindex = {};
  mMatterNodesByNodeid = {};
  mOcfFromMatter = {};
  mOcfToMatter = {};

  /* initialize Matter dict of { DeviceTypeId, DeviceTypeName }*/
  mMatterDeviceTypeName = {
      { { 0x0101 }, "DimmableLight" },
      { { 0x010a }, "OnOffPluginUnit" },
      { { 0x0301 }, "Thermostat" },
      { { 0x002b }, "Fan" }
  };

  /* initialize Matter dict of { ClusterId, ClusterName }*/
  mMatterClusterIdName = {
      { { 0x0006 }, "OnOff" },
      { { 0x0008 }, "LevelControl" },
      { { 0x0201 }, "Thermostat" },
      { { 0x0202 }, "FanControl" }
  };

  /* initialize OCF dict of { OCF Device Type, OCF Device Name } */
  mOcfDeviceName = {
      { { "oic.d.light.smart", "oic.d.light" }, "SmartLight" },
      { { "oic.d.smartplug" }, "SmartPlug" },
      { { "oic.d.thermostat" }, "Thermostat" },
      { { "oic.d.fan" }, "Fan" }
  };

  /* initialize OCF dict of { ResourceType, ResourceName }*/
  mOcfResourceName = {
      { "oic.r.switch.binary", "BinarySwitch" },
      { "oic.r.light.dimming", "Dimming" },
      { "oic.r.temperature", "Temperature" }
  };


  /* --------------------------------------------------------------------------
   * Register OCF <-> Matter translators
   * -------------------------------------------------------------------------*/

  /* ===== OCF -> Matter ===== */

  /* ----- OCF Smart Light -> matter Dimmable Light ----- */
  /* oic.r.switch.binary */
  ResourceToClusterMapper binarySwitchResourceForLight { "onoff", set<DeviceTypeId> {0x0101} };
  /* oic.r.switch.binary:value */
  binarySwitchResourceForLight.P2AMapper()["value"] = std::make_shared<ValueToOnOff> ( "onoff", set<DeviceTypeId> {0x0101}  );

  /* oic.r.light.dimming */
  ResourceToClusterMapper dimmingResourceForLight { "levelcontrol", set<DeviceTypeId> {0x0101} };
  /* oic.r.light.dimming:dimmingSetting */
  dimmingResourceForLight.P2AMapper()["dimmingSetting"] = std::make_shared<DimmingSettingToCurrentLevel> ( "levelcontrol", set<DeviceTypeId> {0x0101} );

  DeviceToEndpointMapper smartLightDevice { set<DeviceTypeId> {0x0101} };
  smartLightDevice.R2CMapper()["oic.r.switch.binary"] = binarySwitchResourceForLight;
  smartLightDevice.R2CMapper()["oic.r.light.dimming"] = dimmingResourceForLight;

  mOcfToMatter[ {"oic.d.light.smart", "oic.d.light"} ] = smartLightDevice;


  /* ----- OCF Smart Plug -> Matter On/Off Plug-in ----- */
  /* oic.r.switch.binary */
  ResourceToClusterMapper binarySwitchResourceForPlug { "onoff", set<DeviceTypeId> {0x010a} };
  /* oic.r.switch.binary:value */
  binarySwitchResourceForPlug.P2AMapper()["value"] = std::make_shared<ValueToOnOff> ( "onoff", set<DeviceTypeId> {0x010a} );

  DeviceToEndpointMapper smartPlugDevice { set<DeviceTypeId> {0x010a} };
  smartPlugDevice.R2CMapper()["oic.r.switch.binary"] = binarySwitchResourceForPlug;

  mOcfToMatter[ { "oic.d.smartplug" } ] = smartPlugDevice;


  /* ----- OCF Thermostat -> Matter Thermostat ----- */
  /* oic.r.temperature */
  ResourceToClusterMapper temperatureResourceForThermostat { "thermostat", set<DeviceTypeId> {0x0301} };
  /* oic.r.temperature:temperature */
  temperatureResourceForThermostat.P2AMapper()["temperature"] = std::make_shared<TemperatureToLocalTemperature> ( "thermostat", set<DeviceTypeId> {0x0301} );
  /* oic.r.temperature:coolSetpoint */
  temperatureResourceForThermostat.P2AMapper()["coolSetpoint"] = std::make_shared<CoolSetpointToCoolingSetpoint> ( "thermostat", set<DeviceTypeId> {0x0301} );
  /* oic.r.temperature:heatSetpoint */
  temperatureResourceForThermostat.P2AMapper()["heatSetpoint"] = std::make_shared<HeatSetpointToHeatingSetpoint> ( "thermostat", set<DeviceTypeId> {0x0301} );

  DeviceToEndpointMapper thermostatDevice { set<DeviceTypeId> {0x0301} };
  thermostatDevice.R2CMapper()["oic.r.temperature"] = temperatureResourceForThermostat;

  mOcfToMatter[ { "oic.d.thermostat" } ] = thermostatDevice;


  /* ----- OCF Fan -> Matter Fan ----- */
  /* oic.r.switch.binary */
  static ResourceToClusterMapper binarySwitchResourceForFan { "fancontrol", set<DeviceTypeId> {0x002b} };
  /* oic.r.switch.binary:value */
  binarySwitchResourceForFan.P2AMapper()["value"] = std::make_shared<ValueToFanMode> ( "fancontrol", set<DeviceTypeId> {0x002b} );

  static DeviceToEndpointMapper fanDevice { set<DeviceTypeId> {0x002b} };
  fanDevice.R2CMapper()["oic.r.switch.binary"] = binarySwitchResourceForFan;

  mOcfToMatter[ { "oic.d.fan" } ] = fanDevice;


  /* ===== OCF <- Matter ===== */

  /* ----- OCF Smart Light <- matter Dimmable Light ----- */
  /* Onnoff cluster */
  ResourceFromClusterMapper onoffClusterForLight { "oic.r.switch.binary", set<string, std::less<>> {"oic.d.light.smart", "oic.d.light"} };
  /* onoff cluster:onoff */
  onoffClusterForLight.PFromAMapper()[0x0000] = std::make_shared<ValueFromOnOff> ( "value", "oic.r.switch.binary", set<string, std::less<>>{"oic.d.light.smart", "oic.d.light"} );

  /* LevelControl cluster */
  ResourceFromClusterMapper levelControlClusterForLight { "oic.r.light.dimming", set<string, std::less<>>{"oic.d.light.smart", "oic.d.light"} };
  /* LevelControl cluster:CurrentLevel */
  levelControlClusterForLight.PFromAMapper()[0x0000] = std::make_shared<DimmingSettingFromCurrentLevel> ( "dimmingSetting", "oic.r.light.dimming", set<string, std::less<>>{"oic.d.light.smart", "oic.d.light"} );
  /* LevelControl cluster:MinLevel */
  levelControlClusterForLight.PFromAMapper()[0x0002] = std::make_shared<RangeFromMinLevel> ( "range", "oic.r.light.dimming", set<string, std::less<>>{"oic.d.light.smart", "oic.d.light"} );
  /* LevelControl cluster:MaxLevel */
  levelControlClusterForLight.PFromAMapper()[0x0003] = std::make_shared<RangeFromMaxLevel> ( "range", "oic.r.light.dimming", set<string, std::less<>>{"oic.d.light.smart", "oic.d.light"} );

  DeviceFromEndpointMapper dimmableLightEndpoint { set<string, std::less<>>{ "oic.d.light.smart", "oic.d.light" } };
  dimmableLightEndpoint.RFromCMapper()[0x0006] = onoffClusterForLight;
  dimmableLightEndpoint.RFromCMapper()[0x0008] = levelControlClusterForLight;

  mOcfFromMatter[ { 0x0101 } ] = dimmableLightEndpoint;


  /* ----- OCF Smart plug <- Matter On/Off Plug-in ----- */
  /* Onnoff cluster */
  ResourceFromClusterMapper onoffClusterForPlugin { "oic.r.switch.binary", set<string, std::less<>>{"oic.d.smartplug"} };
  /* onoff cluster:onoff */
  onoffClusterForPlugin.PFromAMapper()[0x0000] = std::make_shared<ValueFromOnOff> ( "value", "oic.r.switch.binary", set<string, std::less<>>{"oic.d.smartplug"} );

  DeviceFromEndpointMapper onOffPluginEndpoint { set<string, std::less<>>{ "oic.d.smartplug" } };
  onOffPluginEndpoint.RFromCMapper()[0x0006] = onoffClusterForPlugin;

  mOcfFromMatter[ { 0x010a } ] = onOffPluginEndpoint;


  /* ----- OCF Thermostat <- Matter Thermostat ----- */
  /* Thermostat cluster */
  ResourceFromClusterMapper thermostatClusterForThermostat { "oic.r.temperature", set<string, std::less<>>{"oic.d.thermostat"} };
  /* Thermostat cluster:LocalTemperature */
  thermostatClusterForThermostat.PFromAMapper()[0x0000] = std::make_shared<TemperatureFromLocalTemperature> ( "temperature", "oic.r.temperature", set<string, std::less<>>{"oic.d.thermostat"} );
  /* Thermostat cluster:OccupiedCoolingSetpoint */
  thermostatClusterForThermostat.PFromAMapper()[0x0011] = std::make_shared<CoolSetpointFromCoolingSetpoint> ( "coolSetpoint", "oic.r.temperature", set<string, std::less<>>{"oic.d.thermostat"} );
  /* Thermostat cluster:OccupiedHeatingSetpoint */
  thermostatClusterForThermostat.PFromAMapper()[0x0012] = std::make_shared<HeatSetpointFromHeatingSetpoint> ( "heatSetpoint", "oic.r.temperature", set<string, std::less<>>{"oic.d.thermostat"} );

  DeviceFromEndpointMapper thermostatEndpoint { set<string, std::less<>>{ "oic.d.thermostat" } };
  thermostatEndpoint.RFromCMapper()[0x0201] = thermostatClusterForThermostat;

  mOcfFromMatter[ { 0x0301 } ] = thermostatEndpoint;


  /* ----- OCF Fan <- Matter Fan ----- */
  /* Thermostat cluster */
  ResourceFromClusterMapper fanControlClusterForFan { "oic.r.switch.binary", set<string, std::less<>>{"oic.d.fan"} };
  /* Thermostat cluster:LocalTemperature */
  fanControlClusterForFan.PFromAMapper()[0x0000] = std::make_shared<ValueFromFanMode> ( "value", "oic.r.switch.binary", set<string, std::less<>>{"oic.d.fan"} );

  DeviceFromEndpointMapper fanEndpoint { set<string, std::less<>>{ "oic.d.fan" } };
  fanEndpoint.RFromCMapper()[0x0202] = fanControlClusterForFan;

  mOcfFromMatter[ { 0x002b } ] = fanEndpoint;


#ifdef OC_BRG_DEBUG
  for (auto i: mOcfToMatter) {
    cout << "DeviceType: ";
    for (const auto & j: i.first) {
      cout << j << " ";
    }
    cout << endl;

    i.second.Print();
    cout << endl;
  }

  for (auto i: mOcfFromMatter) {
    cout << "DeviceTypeID: ";
    for (auto j: i.first) {
      cout << j << " ";
    }
    cout << endl;

    i.second.Print();
    cout << endl;
  }
#endif
}


void MatterTranslator::Shutdown(void)
{
  /* ----- 2. Destroy all VODs and corresponding MatterNode caches ----- */
  ResetVODs();

  /* ----- 1. Destroy all Dicts ----- */
  mMatterDeviceTypeName.clear();
  mMatterClusterIdName.clear();
  mOcfDeviceName.clear();
  mOcfResourceName.clear();

  mMatterNodesByDeviceindex.clear();
  mMatterNodesByNodeid.clear();

  /* ----- 3. Destroy OCF-to-Matter Mapper & OCF-from-Matter Mapper ----- */
  mOcfToMatter.clear();
  mOcfFromMatter.clear();
}



/*
 * @brief Create VOD corresponding to "mDeviceType"
 *
 * @param matterEp A pair of { NodeId, EndpointId } to create corresponding VDO's name
 * @param matterDeviceTypes A set of DeviceTypeIds to find corredponding OCF Device Types
 * @param deviceIndex A device index, index of newly created VOD will be stored
 * @return 0:success <0:failure
 */
int DeviceFromEndpointMapper::CreateVOD(const pair<NodeId, EndpointId> & matterEp, const set<DeviceTypeId> & matterDeviceTypes, size_t *deviceIndex) const
{
#ifdef OC_BRG_DEBUG
  for (const auto & i: mDeviceType) {
    OC_BRG_LOG("DeviceType: %s", i.c_str());
  }
  for (const auto & resource : mMapper) {
    OC_BRG_LOG("  |_ ResourceType: %s", resource.second.ResourceType().c_str());
  }
#endif

  oc_uuid_t vId;
  char vIdStr[OC_UUID_LEN];

  /* prepare info for new VOD */
  /* v_id */
  oc_gen_uuid(&vId);
  oc_uuid_to_str(&vId, vIdStr, OC_UUID_LEN);

  /* n */
  /*
   * XXX <2023/12/06> DeviceFromEndpointMapper::CreateVOD() : add device index to 'n'
   * => it is difficult.. because device index is decided after hand over 'n' to
   * `oc_bridge_add_virtual_device()`.
   */
  string n = "VOD_" + MatterTranslator::mMatterDeviceTypeName[matterDeviceTypes] + "@" + to_string(matterEp.first) + ":" + to_string(matterEp.second);

  /* rt */
  auto ocfDevType = mDeviceType.begin();

  /* create VOD */
  if (!(*deviceIndex = oc_bridge_add_virtual_device((const uint8_t *)vIdStr, OC_UUID_LEN,
        "matter", "/oic/d", ocfDevType->c_str(),
        n.c_str(), MatterTranslator::mOcfSpecVersion.c_str(),
        MatterTranslator::mOcfDmVersion.c_str(), nullptr, nullptr))) {
    OC_BRG_LOG("VOD creation failed!");
    return -1;
  }

  OC_BRG_LOG("device type: %s", ocfDevType->c_str());

  while (true) {
    if (++ocfDevType == mDeviceType.end())
      break;
    OC_BRG_LOG("device type: %s", ocfDevType->c_str());
    oc_device_bind_resource_type(*deviceIndex, ocfDevType->c_str());
  }

  /* the immutable_device_identifier ("piid") */
  oc_uuid_t piid;
  oc_gen_uuid(&piid);
  oc_set_immutable_device_identifier(*deviceIndex, &piid);

  OC_BRG_LOG("new VOD (device index: %ld) was successfully created..", *deviceIndex);

  return 0;
}


/*
 * @brief Create Application Resource corresponding to "mResourceType"
 *
 * @param deviceTypes Device types of VOD where newly created Resource will belong to
 * @param deviceIndex A device index of VOD where newly created Resource will belong to..
 * @return 0:success, <0:failure
 */
int ResourceFromClusterMapper::CreateResource(const std::set<std::string, std::less<>> & deviceTypes, size_t deviceIndex) const
{
  OC_BRG_LOG("  |_ ResourceType: %s", mResourceType.c_str());

#ifdef OC_BRG_DEBUG
  const oc_device_info_t *vod = oc_core_get_device_info(deviceIndex);
  if (!vod) {
    OC_BRG_LOG("VOD (device index: %ld) is not found!", deviceIndex);
    return -1;
  }
#endif

  /* create App Resources */
  /* n */
#if 0
  string n = g_MatterTranslator.mOcfResourceName[mResourceType] + "_of_" + oc_string(vod->name);
#endif

  /* uri */
  string uri = "/" + /*oc_string(vod->name)*/ MatterTranslator::mOcfDeviceName[deviceTypes] + "/" + MatterTranslator::mOcfResourceName[mResourceType];

  oc_resource_t *r = oc_new_resource(nullptr, uri.c_str(), 1, deviceIndex);
  oc_resource_bind_resource_type(r, mResourceType.c_str());
  oc_resource_bind_resource_interface(r, OC_IF_RW);
  oc_resource_set_default_interface(r, OC_IF_RW);
  oc_resource_set_discoverable(r, true);
  oc_resource_set_request_handler(r, OC_GET, VODResourceGetHandler, nullptr);
  oc_resource_set_request_handler(r, OC_POST, VODResourcePostHandler, nullptr);
  oc_resource_set_request_handler(r, OC_PUT, VODResourcePostHandler, nullptr);
  oc_add_resource(r);

  OC_BRG_LOG("new Resource (rt: \"%s\", uri: \"%s\", device index: %ld) was successfully created..",
      mResourceType.c_str(), uri.c_str(), deviceIndex);

  /* Set Introspection Device Data */
  /*
   * TODO4ME <2023/11/26> PropertyFromAttributeMapper::CreateResource() : implement later
   */
#if 0
  set_idd_from_file("dummy_bridge_virtual_light_IDD.cbor", deviceIndex);
#endif

  return 0;
}



/* --------------------------------------------------------------------------
 * Utility function
 * -------------------------------------------------------------------------*/

char **MatterTranslator::ConvertStrToTokenArray(const string & cmd, int *size)
{
  vector<string> token_list;
  istringstream iss(cmd);

  string token;
  while (getline(iss, token, ' ')) {
    token_list.push_back(token);
  }

  *size = (int)token_list.size();
  char **token_array = new char*[*size];

  int i = 0;
  for (const auto & item : token_list) {
    token_array[i] = new char[item.size() + 1];
    strcpy(token_array[i], item.c_str());
    i++;
  }

  return token_array;
}


void MatterTranslator::FreeTokenArray(char **token_array, int size)
{
  for (int i=0; i<size; i++) {
    delete[] token_array[i];
  }
  delete[] token_array;

  return;
}


set<string, std::less<>> MatterTranslator::ConvertStrarrayToSet(const oc_string_array_t &array)
{
  set<string, std::less<>> newSet {};

  for (int i=0; i < (int)oc_string_array_get_allocated_size(array); i++) {
    newSet.emplace(oc_string_array_get_item(array, i));
  }

  return newSet;
}


pair<string, string> MatterTranslator::SplitURI(const string & uriStr)
{
  /* find first "/" */
  auto first = uriStr.find("/");

  /* extract device id/device name */
  auto device = uriStr.substr(0, first);

  /* extract remaining part.. */
  auto path = uriStr.substr(first+1, uriStr.size());

  return { device, "/" + path };
}

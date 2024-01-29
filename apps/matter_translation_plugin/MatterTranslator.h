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

#pragma once

#include "common/ecosystem_command.h"

#include "oc_api.h"
#include "port/oc_clock.h"
#include "oc_core_res.h"
#include "oc_collection.h"
#include "oc_bridge.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>

#include "commands/common/CHIPCommand.h"

#include "MatterNode.h"

class DeviceToEndpointMapper;
class DeviceFromEndpointMapper;

/**
 * @class MatterTranslator
 */
struct MatterTranslator {
public:
  /**
   * @brief Matter command type
   */
  enum class MatterCommandType {
    MATTER_NONE,  ///< MATTER_NONE
    MATTER_SYSTEM,///< MATTER_SYSTEM : System command. e.g. pairing
    MATTER_READ,  ///< MATTER_READ : Read command
    MATTER_WRITE, ///< MATTER_WRITE : Write command
    MATTER_INVOKE ///< MATTER_INVOKE : Invoke command
  };

  /**
   * @brief OCF <-> Matter Transaction type
   */
  enum class TransactionTranslationMode {
    OCF_TO_MATTER_RETRIEVE,   ///< OCF_TO_MATTER_RETRIEVE
    OCF_TO_MATTER_UPDATE,     ///< OCF_TO_MATTER_UPDATE
    OCF_FROM_MATTER_RETRIEVE, ///< OCF_FROM_MATTER_RETRIEVE
    OCF_FROM_MATTER_UPDATE    ///< OCF_FROM_MATTER_UPDATE
  };

  /**
   * @brief OCF -> Matter Property translation type
   */
  enum class PropertyTranslationMode {
    RETRIEVE_PROPERTY_TO_ATTRIBUTE,         ///< RETRIEVE_PROPERTY_TO_ATTRIBUTE : read (property -> attribute)
    UPDATE_PROPERTY_TO_ATTRIBUTE,           ///< UPDATE_PROPERTY_TO_ATTRIBUTE : update (property -> attribute)
    UPDATE_PROPERTY_TO_COMMAND,             ///< UPDATE_PROPERTY_TO_COMMAND : update (property -> command)
    UPDATE_PROPERTY_TO_COMMAND_WITH_PAYLOAD ///< UPDATE_PROPERTY_TO_COMMAND_WITH_PAYLOAD : update (property -> command with payload)
  };

  static const constexpr char *mFinalOcfToMatterMode = "FinalOcfToMatterMode";
  static const constexpr char *mResultStatus = "ResultStatus";

  static std::string mOcfSpecVersion;              ///< OCF spec version
  static std::string mOcfDmVersion;                ///< OCF Data model version

  static std::map<std::set<DeviceTypeId>, std::string> mMatterDeviceTypeName;          ///< dict : Matter DeviceTypeId -> Matter DeviceTypeName
  static std::map<ClusterId, std::string> mMatterClusterIdName;                        ///< dict : Matter ClusterId -> Matter ClusterName
  static std::map<std::set<std::string, std::less<>>, std::string> mOcfDeviceName;     ///< dict : OCF Device Type -> OCF Device Name
  static std::map<std::string, std::string, std::less<>> mOcfResourceName;             ///< dict : OCF Resoruce Type -> OCF Resource Name

  /**
   * @brief Matter Node list which keeps Matter Nodes corresponding to each OCF VOD
   */
  static std::map<size_t, std::pair<NodeId, EndpointId>> mMatterNodesByDeviceindex;   ///< dict : OCF Device Index -> Matter Endpoint
  static std::map<NodeId, std::shared_ptr<MatterNode>> mMatterNodesByNodeid;          ///< dict : Matter NodeID -> Matter Node Cache entry

  static std::map<std::set<std::string, std::less<>>, DeviceToEndpointMapper> mOcfToMatter;  ///< OCF -> Matter translator (dict : DeviceType => EP DeviceTypeId)
  static std::map<std::set<DeviceTypeId>, DeviceFromEndpointMapper> mOcfFromMatter;          ///< OCF <- Matter translator (dict : DeviceType <= EP DeviceTypeId)

  MatterTranslator() = default;

  /**
   * @brief Initialize Matter Translator (register translators per Device/Resource/Properties)
   * @param ocfSpecVersion OCF spec version
   * @param ocfDmVersion OCF Data Model version
   */
  static void Init(const std::string & ocfSpecVersion, const std::string & ocfDmVersion);

  /**
   * @brief Shutdown Matter Translator (unregister translators per Device/Resource/Properties)
   */
  static void Shutdown(void);

  /* ----- Utility Functions ----- */

  /**
   * @brief Convert string into char *[] array
   * @param cmd String
   * @param size Length of char *[] array
   * @return char *[]
   */
  static char **ConvertStrToTokenArray(const std::string & cmd, int *size);

  /**
   * @brief Free char *[]
   * @param token_array Char *[] array to be freed
   * @param size Length of token_array
   */
  static void FreeTokenArray(char **token_array, int size);

  /**
   * @brief Convert oc string array into std::set
   * @param array oc_string_array_t
   * @return std::set
   */
  static std::set<std::string, std::less<>> ConvertStrarrayToSet(const oc_string_array_t &array);

  /**
   * @brief Split OCF URI string into { <device ID>/<device name>, path of Resource }
   * @param uriStr OCF URI string
   * @return std::pair { <device ID> (or <device name>), path of Resource }
   */
  static std::pair<std::string, std::string> SplitURI(const std::string & uriStr);
};




/* --------------------------------------------------------------------------
 * OCF --> Matter
 * -------------------------------------------------------------------------*/

/*
 * @class DeviceToEndpointMapper
 *
 * <OCF Device Type> : {
 *   mDeviceTypeId : <Matter DeviceTypeId>,
 *   <OCF Resource Type1>: {
 *     mClusterId : <Matter ClusterId1>
 *     <OCF Property Name1>: <Matter AttributeId1>,
 *     <OCF Property Name2>: <Matter AttributeId2>
 *   },
 *   <OCF Resource Type2>: {
 *     mClusterName : <Matter ClusterId2>
 *     <OCF Property Name1>: <Matter AttributeId1>,
 *     <OCF Property Name2>: <Matter AttributeId2>
 *   }
 * }
 */

class ResourceToClusterMapper;
class PropertyToAttributeMapper;
class AttributeOrCommand;
/*
 * OCF Device -> Matter Endpoint
 */
class DeviceToEndpointMapper : public MatterTranslator {
private:
  std::map<std::string, ResourceToClusterMapper, std::less<>> mMapper;   ///< Resource Type => Cluster name
  std::set<DeviceTypeId> mDeviceTypeId;                                  ///< Matter Device Types

public:

  /* ----- Contructor / Destructor ----- */
  explicit DeviceToEndpointMapper(const std::set<DeviceTypeId> & deviceTypeId) :
                        MatterTranslator(), mDeviceTypeId(deviceTypeId) {}
  DeviceToEndpointMapper() = default;
  virtual ~DeviceToEndpointMapper() = default;

  /* ----- Member functions ----- */
  auto & R2CMapper() { return mMapper; }
  auto & DevicetypeId() { return mDeviceTypeId; }
  virtual void Print();
};


/*
 * OCF Resource -> Matter Cluster
 */
class ResourceToClusterMapper : public DeviceToEndpointMapper {
private:
  std::map<std::string, std::shared_ptr<PropertyToAttributeMapper>, std::less<>> mMapper;   ///< Property Name => Attribute Id / Command Id to be invoked
  std::string mClusterName;                                                                 ///< Matter Cluster Name
  static Json::Value jsonRoot;                                                              ///< json root object to store translation results
  static Json::StreamWriterBuilder jsonWriter;                                              ///< json writer to build singleline json string

public:

  /* ----- Contructor / Destructor ----- */
  ResourceToClusterMapper(const std::string & clusterName, const std::set<DeviceTypeId> & deviceTypeId) :
                          DeviceToEndpointMapper(deviceTypeId), mClusterName(clusterName) {}
  ResourceToClusterMapper() = default;
  ~ResourceToClusterMapper() override = default;

  /* ----- Member functions ----- */
  auto & P2AMapper() { return mMapper; }
  auto & ClusterName() { return mClusterName; }
  static auto & JsonRoot() { return jsonRoot; }
  static auto & JsonWriter() { return jsonWriter; }
  static void Reset() { jsonRoot = Json::Value{}; }
  void Print() override;
};



/*
 * OCF Property -> Matter Attribute
 */
class PropertyToAttributeMapper : public ResourceToClusterMapper {
private:
  std::map<PropertyTranslationMode, std::map<int, uint32_t>> mMapper;   ///< final translator for OCF Property:
                                                                        ///< { translationmode, { index, Matter AttributeId (or CommandID) } }

public:
  /* ----- Contructor / Destructor ----- */
  using ResourceToClusterMapper::ResourceToClusterMapper;
  PropertyToAttributeMapper() = default;
  ~PropertyToAttributeMapper() override = default;

  /* ----- Member functions ----- */
  /**
   * @brief
   * for RETRIEVE:
   * - translate OCF Property to Matter attributeID, and accumulate the result to jsonRoot
   *
   * for UPDATE:
   * - translate OCF Property to Matter attributeID with its value (or CommandID with payload),
   *   and accumulate the result to jsonRoot
   *
   * @param translateMode Translation mode of this Transaction
   * @param value for RETRIEVE : not used, for UPDATE : OCF Property value to be translated
   */
  virtual void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{} ) = 0;

  auto & Mapper() { return mMapper; }
  void Print() override;
};




/* --------------------------------------------------------------------------
 * OCF <-- Matter
 * -------------------------------------------------------------------------*/

/*
 * @class DeviceFromEndpointMapper
 *
 * <Matter DeviceTypeId> : {
 *   mDeviceType : <OCF Device Type string>,
 *   <Matter ClusterId1>: {
 *     mResourceType : <OCF Resource Type string1>,
 *     <Matter AttributeId1> : <OCF Property Name1>,
 *     <Matter AttributeId2> : <OCF Property Name2>
 *   },
 *   <Matter ClusterId2>: {
 *     mResourceType : <OCF Resource Type string2>
 *     <Matter AttributeId1> : <OCF Property Name1>,
 *     <Matter AttributeId2> : <OCF Property Name2>
 *   }
 * }
 */
class ResourceFromClusterMapper;
/*
 * OCF Device <- Matter Endpoint
 */
class DeviceFromEndpointMapper : public MatterTranslator {
private:
  std::map<ClusterId, ResourceFromClusterMapper> mMapper;  ///< Resource Type <= Cluster Id
  std::set<std::string, std::less<>> mDeviceType;          ///< OCF Device Types

public:

  /* ----- Contructor / Destructor ----- */
  explicit DeviceFromEndpointMapper(const std::set<std::string, std::less<>> & deviceType) :
                          MatterTranslator(), mDeviceType(deviceType) {}
  DeviceFromEndpointMapper() = default;
  virtual ~DeviceFromEndpointMapper() = default;

  /* ----- Member functions ----- */
  auto & RFromCMapper() { return mMapper; }
  auto & Devicetype() { return mDeviceType; }

  /**
   * @brief Create VOD corresponding to "mDeviceType"
   *
   * @param matterEp A pair of { NodeId, EndpointId } to create corresponding VDO's name
   * @param matterDeviceTypes A set of DeviceTypeIds to find corredponding OCF Device Types
   * @param deviceIndex A device index, index of newly created VOD will be stored
   * @return 0:success <0:failure
   */
  int CreateVOD(const std::pair<NodeId, EndpointId> & matterEp, const std::set<DeviceTypeId> & matterDeviceTypes, size_t *deviceIndex) const;

  virtual void Print();
};


/*
 * OCF Resource <- Matter Cluster
 */
class PropertyFromAttributeMapper;
struct ResourceFromClusterMapper : public DeviceFromEndpointMapper {
private:
  std::map<AttributeId, std::shared_ptr<PropertyFromAttributeMapper>> mMapper;   ///< Property Name <= Attribute Id
  std::string mResourceType;                                                     ///< OCF Resource Types
  static Json::Value jsonRoot;                                                   ///< json root object to store translation results

public:
  /* ----- Contructor / Destructor ----- */
  ResourceFromClusterMapper(const std::string & resourceType, const std::set<std::string, std::less<>> & deviceType):
                            DeviceFromEndpointMapper(deviceType), mResourceType(resourceType) {}
  ResourceFromClusterMapper() = default;
  ~ResourceFromClusterMapper() override = default;

  /* ----- Member functions ----- */
  auto & PFromAMapper() { return mMapper; }
  static auto & JsonRoot() { return jsonRoot; }
  const auto & ResourceType() const { return mResourceType; }
  /**
   * @brief Create Application Resource corresponding to "mResourceType"
   *
   * @param deviceTypes Device types of VOD where newly created Resource will belong to
   * @param deviceIndex A device index of VOD where newly created Resource will belong to
   * @return 0:success, <0:failure
   */
  int CreateResource(const std::set<std::string, std::less<>> & deviceTypes, size_t deviceIndex) const;

  static void Reset() { JsonRoot() = Json::Value{}; }
  void Print() override;
};


/*
 * OCF Property <- Matter Attribute
 */
class PropertyFromAttributeMapper : public ResourceFromClusterMapper {
public:
  std::string mPropertyName;   ///< OCF Property Name

  /* ----- Contructor / Destructor ----- */
  PropertyFromAttributeMapper(const std::string & propertyName, const std::string & resourceType, const std::set<std::string, std::less<>> & deviceType) :
                              ResourceFromClusterMapper(resourceType, deviceType), mPropertyName(propertyName) {}
  PropertyFromAttributeMapper() = default;
  ~PropertyFromAttributeMapper() override = default;

  /* ----- Member functions ----- */
  /**
   * @brief
   * for RETRIEVE:
   * - translate Matter attribute to OCF property, and accumulate the result to jsonRoot
   *
   * for UPDATE:
   * - nothing
   *
   * @param translateMode Translation mode
   * @param value For RETRIEVE : Matter attribute value to be translated, for UPDATE : status code
   */
  virtual void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) = 0;
  void Print() override;
};




/* --------------------------------------------------------------------------
 * OCF --> Matter : implementations
 * -------------------------------------------------------------------------*/

/*
 * OCF Binary Switch Resource ("oic.r.switch.binary:value")
 */
class ValueToOnOff: public PropertyToAttributeMapper {
public:
  /* ----- Contructor / Destructor ----- */
  ValueToOnOff(const std::string & clusterName, const std::set<DeviceTypeId> & deviceTypeId) :
              PropertyToAttributeMapper(clusterName, deviceTypeId)
  {
    Mapper()[PropertyTranslationMode::RETRIEVE_PROPERTY_TO_ATTRIBUTE][0] = 0x0000; // value -> OnOff (Attribute)
    Mapper()[PropertyTranslationMode::UPDATE_PROPERTY_TO_COMMAND][0] = 0x00; // false -> off (Command)
    Mapper()[PropertyTranslationMode::UPDATE_PROPERTY_TO_COMMAND][1] = 0x01; // true -> on (Command)
  }
  ValueToOnOff() = default;
  ~ValueToOnOff() final = default;

  /* ----- Member functions ----- */
  void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) final
  {
    switch (translateMode) {
    case TransactionTranslationMode::OCF_TO_MATTER_RETRIEVE:
      JsonRoot()[std::to_string(Mapper()[PropertyTranslationMode::RETRIEVE_PROPERTY_TO_ATTRIBUTE][0])] = 0;
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    case TransactionTranslationMode::OCF_TO_MATTER_UPDATE:
      if (value.asBool() == true) {
        JsonRoot()[std::to_string(Mapper()[PropertyTranslationMode::UPDATE_PROPERTY_TO_COMMAND][1])] = "{}";
      } else {
        JsonRoot()[std::to_string(Mapper()[PropertyTranslationMode::UPDATE_PROPERTY_TO_COMMAND][0])] = "{}";
      }
      JsonRoot()[mFinalOcfToMatterMode] = (int)PropertyTranslationMode::UPDATE_PROPERTY_TO_COMMAND;
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    default:
      break;
    }
  }
};


/*
 * OCF Binary Switch Resource ("oic.r.switch.binary:value")
 */
class ValueToFanMode: public PropertyToAttributeMapper {

public:
  /* ----- Contructor / Destructor ----- */
  ValueToFanMode(const std::string & clusterName, const std::set<DeviceTypeId> & deviceTypeId) :
    PropertyToAttributeMapper(clusterName, deviceTypeId)
  {
    Mapper()[PropertyTranslationMode::RETRIEVE_PROPERTY_TO_ATTRIBUTE][0] = 0x00; // value -> FanMode (Attribute)
    Mapper()[PropertyTranslationMode::UPDATE_PROPERTY_TO_ATTRIBUTE][0] = 0x00; // value -> FanMode (Attribute)
  }
  ValueToFanMode() = default;
  ~ValueToFanMode() final = default;

  /* ----- Member functions ----- */
  void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) final
  {
    switch (translateMode) {
    case TransactionTranslationMode::OCF_TO_MATTER_RETRIEVE:
      JsonRoot()[std::to_string(Mapper()[PropertyTranslationMode::RETRIEVE_PROPERTY_TO_ATTRIBUTE][0])] = 0;
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    case TransactionTranslationMode::OCF_TO_MATTER_UPDATE:
      if (value.asBool() == true) {
        JsonRoot()[std::to_string(Mapper()[PropertyTranslationMode::UPDATE_PROPERTY_TO_ATTRIBUTE][0])] = "5"; // auto
      } else {
        JsonRoot()[std::to_string(Mapper()[PropertyTranslationMode::UPDATE_PROPERTY_TO_ATTRIBUTE][0])] = "0"; // off
      }
      JsonRoot()[mFinalOcfToMatterMode] = (int)PropertyTranslationMode::UPDATE_PROPERTY_TO_ATTRIBUTE;
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    default:
      break;
    }
  }
};


/*
 * OCF Dimming Resource ("oic.r.light.dimming:dimmingSetting")
 */
class DimmingSettingToCurrentLevel : public PropertyToAttributeMapper {

public:
  /* ----- Contructor / Destructor ----- */
  DimmingSettingToCurrentLevel(const std::string & clusterName, const std::set<DeviceTypeId> & deviceTypeId) :
    PropertyToAttributeMapper(clusterName, deviceTypeId)
  {
    Mapper()[PropertyTranslationMode::RETRIEVE_PROPERTY_TO_ATTRIBUTE][0] = 0x0000; // dimmingSetting -> CurrentLevel (Attribute)
    Mapper()[PropertyTranslationMode::UPDATE_PROPERTY_TO_COMMAND_WITH_PAYLOAD][0] = 0x00; // dimmingSetting -> MoveToLevel (Command)
  }
  DimmingSettingToCurrentLevel() = default;
  ~DimmingSettingToCurrentLevel() final = default;

  /* ----- Member functions ----- */
  void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) final
  {
    switch (translateMode) {
    case TransactionTranslationMode::OCF_TO_MATTER_RETRIEVE:
      JsonRoot()[std::to_string(Mapper()[PropertyTranslationMode::RETRIEVE_PROPERTY_TO_ATTRIBUTE][0])] = 0;
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    case TransactionTranslationMode::OCF_TO_MATTER_UPDATE: {
      Json::Value payload;
      payload["0"] = value.asUInt(); // Level
      payload["1"] = 0; // TransitionTime
      payload["2"] = 0; // OptionsMask
      payload["3"] = 0; // OptionsOverride

      JsonRoot()[std::to_string(Mapper()[PropertyTranslationMode::UPDATE_PROPERTY_TO_COMMAND_WITH_PAYLOAD][0])] = /*"'" +*/ Json::writeString(JsonWriter(), payload) /*+ "'"*/;
      JsonRoot()[mFinalOcfToMatterMode] = (int)PropertyTranslationMode::UPDATE_PROPERTY_TO_COMMAND_WITH_PAYLOAD;

      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;
    }

    default:
      break;
    }
  }
};


/*
 * OCF Temperature Resource ("oic.r.temperature:temperature")
 */
class TemperatureToLocalTemperature: public PropertyToAttributeMapper {
public:
  /* ----- Contructor / Destructor ----- */
  TemperatureToLocalTemperature(const std::string & clusterName, const std::set<DeviceTypeId> & deviceTypeId) :
    PropertyToAttributeMapper(clusterName, deviceTypeId)
  {
    Mapper()[PropertyTranslationMode::RETRIEVE_PROPERTY_TO_ATTRIBUTE][0] = 0x0000; // temperature -> LocalTemperature (Attribute)
    Mapper()[PropertyTranslationMode::UPDATE_PROPERTY_TO_COMMAND_WITH_PAYLOAD][0] = 0x00; // temperature -> SetpointRaiseLower (Command)
  }
  TemperatureToLocalTemperature() = default;
  ~TemperatureToLocalTemperature() final = default;

  /* ----- Member functions ----- */
  void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) final
  {
    switch (translateMode) {
    case TransactionTranslationMode::OCF_TO_MATTER_RETRIEVE:
      JsonRoot()[std::to_string(Mapper()[PropertyTranslationMode::RETRIEVE_PROPERTY_TO_ATTRIBUTE][0])] = 0;
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    case TransactionTranslationMode::OCF_TO_MATTER_UPDATE: {
      Json::Value payload;
      payload["0"] = 2;  // Mode field: 2(both)
      payload["1"] = "s:" + std::to_string(value.asUInt()*10); // Amount field : value

      JsonRoot()[std::to_string(Mapper()[PropertyTranslationMode::UPDATE_PROPERTY_TO_COMMAND_WITH_PAYLOAD][0])] = /*"'" +*/ Json::writeString(JsonWriter(), payload) /*+ "'"*/;
      JsonRoot()[mFinalOcfToMatterMode] = (int)PropertyTranslationMode::UPDATE_PROPERTY_TO_COMMAND_WITH_PAYLOAD;
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;
    }

    default:
      break;
    }

  }
};


/*
 * OCF Temperature Resource ("oic.r.temperature:coolSetpoint")
 */
class CoolSetpointToCoolingSetpoint: public PropertyToAttributeMapper {
public:
  /* ----- Contructor / Destructor ----- */
  CoolSetpointToCoolingSetpoint(const std::string & clusterName, const std::set<DeviceTypeId> & deviceTypeId) :
    PropertyToAttributeMapper(clusterName, deviceTypeId)
  {
    Mapper()[PropertyTranslationMode::RETRIEVE_PROPERTY_TO_ATTRIBUTE][0] = 0x0011; // coolSetpoint -> OccupiedCoolingSetpoint (Attribute)
  }
  CoolSetpointToCoolingSetpoint() = default;
  ~CoolSetpointToCoolingSetpoint() final = default;

  /* ----- Member functions ----- */
  void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) final
  {
    switch (translateMode) {
    case TransactionTranslationMode::OCF_TO_MATTER_RETRIEVE:
      JsonRoot()[std::to_string(Mapper()[PropertyTranslationMode::RETRIEVE_PROPERTY_TO_ATTRIBUTE][0])] = 0;
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    default:
      /* coolSetpoint property is read-only... */
      break;
    }
  }
};


/*
 * OCF Temperature Resource ("oic.r.temperature:heatSetpoint")
 */
class HeatSetpointToHeatingSetpoint: public PropertyToAttributeMapper {
public:
  /* ----- Contructor / Destructor ----- */
  HeatSetpointToHeatingSetpoint(const std::string & clusterName, const std::set<DeviceTypeId> & deviceTypeId) :
    PropertyToAttributeMapper(clusterName, deviceTypeId)
  {
    Mapper()[PropertyTranslationMode::RETRIEVE_PROPERTY_TO_ATTRIBUTE][0] = 0x0012; // heatSetpoint -> OccupiedHeatingSetpoint (Attribute)
  }
  HeatSetpointToHeatingSetpoint() = default;
  ~HeatSetpointToHeatingSetpoint() final = default;

  /* ----- Member functions ----- */
  void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) final
  {
    switch (translateMode) {
    case TransactionTranslationMode::OCF_TO_MATTER_RETRIEVE:
      JsonRoot()[std::to_string(Mapper()[PropertyTranslationMode::RETRIEVE_PROPERTY_TO_ATTRIBUTE][0])] = 0;
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    default:
      /* heatSetpoint property is read-only... */
      break;
    }
  }
};



/* --------------------------------------------------------------------------
 * OCF <-- Matter : implementations
 * -------------------------------------------------------------------------*/

/*
 * OCF Binary Switch Resource ("oic.r.switch.binary:value")
 */
class ValueFromOnOff: public PropertyFromAttributeMapper {
public:
  /* ----- Contructor / Destructor ----- */
  using PropertyFromAttributeMapper::PropertyFromAttributeMapper;
  ValueFromOnOff() = default;
  ~ValueFromOnOff() final = default;

  /* ----- Member functions ----- */
  void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) final
  {
    switch (translateMode) {
    case TransactionTranslationMode::OCF_FROM_MATTER_RETRIEVE:
      JsonRoot()[mPropertyName] = value.asBool();
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    case TransactionTranslationMode::OCF_FROM_MATTER_UPDATE:
      JsonRoot()["status"] = value.asUInt();
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    default:
      break;
    }

  }
};


/*
 * OCF Dimming Resource ("oic.r.light.dimming:dimmingSetting")
 */
class DimmingSettingFromCurrentLevel : public PropertyFromAttributeMapper {
public:
  /* ----- Contructor / Destructor ----- */
  using PropertyFromAttributeMapper::PropertyFromAttributeMapper;
  DimmingSettingFromCurrentLevel() = default;
  ~DimmingSettingFromCurrentLevel() final = default;

  /* ----- Member functions ----- */
  void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) final
  {
    switch (translateMode) {
    case TransactionTranslationMode::OCF_FROM_MATTER_RETRIEVE:
      JsonRoot()[mPropertyName] = value.asUInt();
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    case TransactionTranslationMode::OCF_FROM_MATTER_UPDATE:
      JsonRoot()["status"] = value.asUInt();
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    default:
      break;
    }
  }
};


/*
 * OCF Dimming Resource ("oic.r.light.dimming:range")
 */
class RangeFromMinLevel : public PropertyFromAttributeMapper {
public:
  /* ----- Contructor / Destructor ----- */
  using PropertyFromAttributeMapper::PropertyFromAttributeMapper;
  RangeFromMinLevel() = default;
  ~RangeFromMinLevel() final = default;

  /* ----- Member functions ----- */
  void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) final
  {
    switch (translateMode) {
    case TransactionTranslationMode::OCF_FROM_MATTER_RETRIEVE:
      JsonRoot()[mPropertyName][0] = value.asUInt(); // min range
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    case TransactionTranslationMode::OCF_FROM_MATTER_UPDATE:
      JsonRoot()["status"] = value.asUInt();
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    default:
      break;
    }
  }
};


/*
 * OCF Dimming Resource ("oic.r.light.dimming:range")
 */
class RangeFromMaxLevel : public PropertyFromAttributeMapper {
public:
  /* ----- Contructor / Destructor ----- */
  using PropertyFromAttributeMapper::PropertyFromAttributeMapper;
  RangeFromMaxLevel() = default;
  ~RangeFromMaxLevel() final = default;

  /* ----- Member functions ----- */
  void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) final
  {
    switch (translateMode) {
    case TransactionTranslationMode::OCF_FROM_MATTER_RETRIEVE:
      JsonRoot()[mPropertyName][1] = value.asUInt();  // max range
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    case TransactionTranslationMode::OCF_FROM_MATTER_UPDATE:
      JsonRoot()["status"] = value.asUInt();
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    default:
      break;
    }
  }
};


/*
 * OCF Temperature Resource ("oic.r.temperature:temperature")
 */
class TemperatureFromLocalTemperature: public PropertyFromAttributeMapper {
public:
  /* ----- Contructor / Destructor ----- */
  using PropertyFromAttributeMapper::PropertyFromAttributeMapper;
  TemperatureFromLocalTemperature() = default;
  ~TemperatureFromLocalTemperature() final = default;

  /* ----- Member functions ----- */
  void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) final
  {
    switch (translateMode) {
    case TransactionTranslationMode::OCF_FROM_MATTER_RETRIEVE:
      JsonRoot()[mPropertyName] = value.asUInt()/100;  // temperature
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    case TransactionTranslationMode::OCF_FROM_MATTER_UPDATE:
      JsonRoot()["status"] = value.asUInt();
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    default:
      break;
    }
  }
};


/*
 * OCF Temperature Resource ("oic.r.temperature:coolSetpoint")
 */
class CoolSetpointFromCoolingSetpoint: public PropertyFromAttributeMapper {
public:
  /* ----- Contructor / Destructor ----- */
  using PropertyFromAttributeMapper::PropertyFromAttributeMapper;
  CoolSetpointFromCoolingSetpoint() = default;
  ~CoolSetpointFromCoolingSetpoint() final = default;

  /* ----- Member functions ----- */
  void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) final
  {
    switch (translateMode) {
    case TransactionTranslationMode::OCF_FROM_MATTER_RETRIEVE:
      JsonRoot()[mPropertyName] = value.asUInt()/100;  // temperature
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    default:
      /* coolSetpoint property is readonly.. */
      break;
    }
  }
};


/*
 * OCF Temperature Resource ("oic.r.temperature:heatSetpoint")
 */
class HeatSetpointFromHeatingSetpoint: public PropertyFromAttributeMapper {
public:
  /* ----- Contructor / Destructor ----- */
  using PropertyFromAttributeMapper::PropertyFromAttributeMapper;
  HeatSetpointFromHeatingSetpoint() = default;
  ~HeatSetpointFromHeatingSetpoint() final = default;

  /* ----- Member functions ----- */
  void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) final
  {
    switch (translateMode) {
    case TransactionTranslationMode::OCF_FROM_MATTER_RETRIEVE:
      JsonRoot()[mPropertyName] = value.asUInt()/100;  // temperature
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    default:
      /* coolSetpoint property is readonly.. */
      break;
    }
  }
};


/*
 * OCF Binary Switch Resource ("oic.r.switch.binary:value")
 */
class ValueFromFanMode: public PropertyFromAttributeMapper {
public:
  /* ----- Contructor / Destructor ----- */
  using PropertyFromAttributeMapper::PropertyFromAttributeMapper;
  ValueFromFanMode() = default;
  ~ValueFromFanMode() final = default;

  /* ----- Member functions ----- */
  void Translate(TransactionTranslationMode translateMode, const Json::Value &value = Json::Value{}) final
  {
    switch (translateMode) {
    case TransactionTranslationMode::OCF_FROM_MATTER_RETRIEVE:
      if (value.asBool() == 0) {
        // off
        JsonRoot()[mPropertyName] = value.asBool();  // value
      } else {
        // auto
        JsonRoot()[mPropertyName] = 1;  // value
      }
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    case TransactionTranslationMode::OCF_FROM_MATTER_UPDATE:
      JsonRoot()["status"] = value.asUInt();
      OC_BRG_LOG("current jsonRoot: \n%s", JsonRoot().toStyledString().c_str());
      break;

    default:
      break;
    }
  }
};


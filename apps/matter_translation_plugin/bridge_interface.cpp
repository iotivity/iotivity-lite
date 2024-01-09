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
 * Created on: Aug 20, 2023,
 *        Author: Joo-Chul Kevin Lee (rune@etri.re.kr)
 *
 *
 ****************************************************************************/

#include "commands/common/Commands.h"
#include "common/ecosystem_command.h"
#include "bridge_interface.h"
#include "matter_client.h"
#include "MatterTaskHandler.h"

#include "util/oc_list.h"
#include "util/oc_memb.h"
#include "oc_api.h"
#include "port/oc_clock.h"
#include "oc_core_res.h"
#include "oc_collection.h"
#include "oc_export.h"
#include "oc_bridge.h"
#include "oc_rep.h"
#include "MatterNode.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <jansson.h>

#include <map>
#include <string>
#include <iomanip>

using namespace ::chip;
using namespace ::std;

OC_MEMB(g_cliCommandInstanceMemb, cli_command_t, 1);

/*
 * thread waiting for the completion of subtask of each command handler
 */
pthread_mutex_t g_TaskWaiterLock;
pthread_cond_t g_CondTaskIsCompleted;

/*
 * current destination Node ID
 */
NodeId g_DestinationNodeId;

/*
 * keeps information of current running command
 * - to decide which action should be done in ONE COMMON retrieval response callback function..
 */
pthread_mutex_t g_OngoingCommandLock;
MatterTaskHandler::OnGoingCommand g_OngoingCommand;

/*
 * "ReportCommand::OnAttributeData()" is called repeatedly for each attribute data.
 * so this value is used to decide when we wakeup "TaskCompletionWaiter" thread..
 * (we have to wait until every attribute date is received..)
 */
int g_NumOfExpectedAttrData;

/*
 * find "obj_name" in "parent" object, and return "key_name" in the "obj_name"
 */
#if 0
static json_t *
_get_json_item_in_object(const json_t *parent, const char *obj_name, const char *key_name)
{
  const json_t *obj;
  json_t *key;

  if (!(obj = json_object_get(parent, obj_name))) {
    OC_BRG_ERR("object \"%s\" is not found!", obj_name);
    return nullptr;
  }

  if (!(key = json_object_get(obj, key_name))) {
    OC_BRG_ERR("key \"%s\" is not found!", key_name);
    return nullptr;
  }

  return key;
}
#endif


/*---------------------------------------------------------------------------*/
/*
 *  ecosystem-specific callback APIs that this translation plugin provides.
 */
/*---------------------------------------------------------------------------*/

static int
Discover(const char *parsed_command_json_str)
{
  OC_BRG_LOG("json string: %s", parsed_command_json_str);

  Json::Value jsonRoot;
  Json::CharReaderBuilder jsonCharReaderBuilder;
  JSONCPP_STRING jsonErrMsg;

  const unique_ptr<Json::CharReader> jsonStrReader { jsonCharReaderBuilder.newCharReader() };

  /* 1. ----- load json stream ----- */
  VerifyOrReturnValue(
      jsonStrReader->parse(parsed_command_json_str, parsed_command_json_str + strlen(parsed_command_json_str), &jsonRoot, &jsonErrMsg),
      -1, OC_BRG_LOG("command json parsing failed! : %s", jsonErrMsg.c_str()));

  /* 2. ----- build command string ----- */
  string commandStr { "chip-tool " };
  commandStr += (jsonRoot[KEY_CMD][KEY_CMDSTR].asString() + " " + jsonRoot[KEY_SUBCMD][KEY_CMDSTR].asString());

  for (const auto & param : jsonRoot[KEY_SUBCMD][KEY_VALUE]) {
    commandStr += (" " + param.asString());
  }

  OC_BRG_LOG("built command string: \"%s\"", commandStr.c_str());

  /* 2. ----- fire command ----- */
  RUN_MATTER_COMMAND(commandStr);

  return 0;
}


/*
 * thread waiting for the completion of matter command..
 */
static void *
TaskCompletionWaiter(void *data)
{
  (void)data;

  timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += 5;
  int result;
  auto runResult = std::make_unique<int>();

  pthread_mutex_lock(&g_TaskWaiterLock);
  if ((result = pthread_cond_timedwait(&g_CondTaskIsCompleted, &g_TaskWaiterLock, &ts)) == ETIMEDOUT) {
    OC_BRG_ERR("Timed out!, running command failed!");
    *runResult = ETIMEDOUT;
  } else {
    *runResult = result;
  }
  pthread_mutex_unlock(&g_TaskWaiterLock);

  return (void *)runResult.release();
}


/*
 * run matter command
 */
static int
_RunMatterCommand(const string &commandStr, MatterTranslator::MatterCommandType commandType = MatterTranslator::MatterCommandType::MATTER_NONE, int numOfExpectedAttrData = 0)
{
  pthread_t ptTaskCompletionWaiter;
  int *ptReturnValue;
  unique_ptr<int> runResult;

  /* launch thread waiting completion of command... */
  VerifyOrReturnValue(pthread_create(&ptTaskCompletionWaiter, nullptr, TaskCompletionWaiter, nullptr) == 0,
      -1,
      OC_BRG_LOG("TaskCompletionWaiter() thread creation failed!");
      UNSET_ONGOING_COMMAND();
  );

  /* for read cluster command.. */
  if (commandType == MatterTranslator::MatterCommandType::MATTER_READ) {
    g_NumOfExpectedAttrData = numOfExpectedAttrData;
  }

  /* fire matter command */
  OC_BRG_LOG("firing command \"%s\"...", commandStr.c_str());
  RUN_MATTER_COMMAND(commandStr);

  /* wait for the completion of matter command... */
  pthread_join(ptTaskCompletionWaiter, (void **)&ptReturnValue);
  runResult.reset(ptReturnValue);
  VerifyOrReturnValue(*runResult == 0,
      -1,
      OC_BRG_LOG("=====> Command task is resumed! (running command failed (maybe TIMEOUT) !!, runResult: %d) <=====", *runResult);
      UNSET_ONGOING_COMMAND();
  );
  OC_BRG_LOG("=====> Command task is resumed! (running command completed!!, runResult: %d) <=====", *runResult);

  return 0;
}


/*
 * create OCF application Resources per each Matter cluster
 */
static int
_CreateResources(const std::map<ClusterId, std::shared_ptr<MatterCluster>> & targetClusterList,
    DeviceFromEndpointMapper deviceFromEndpointMapper, const size_t & deviceIndex)
{
  for (const auto & cluster : targetClusterList) {
    OC_BRG_LOG("clusterID: %d", cluster.second->mClusterId);

    if (deviceFromEndpointMapper.RFromCMapper().find(cluster.second->mClusterId) != deviceFromEndpointMapper.RFromCMapper().end()) {
      /* create app resources.. */
      auto resourceFromClusterMapper = deviceFromEndpointMapper.RFromCMapper()[cluster.second->mClusterId];

      VerifyOrReturnValue(!resourceFromClusterMapper.CreateResource(deviceFromEndpointMapper.Devicetype(), deviceIndex),
          -1,
          OC_BRG_LOG("Creation of Resource corresponding to %x failed!", cluster.second->mClusterId);
          UNSET_ONGOING_COMMAND();
      );
    }
  }
  return 0;
}


/*
 * create OCF VOD for target Matter EP
 */
static int
_CreateVOD()
{
  auto node = MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId];
  size_t deviceIndex;

  /* create VODs corresponding to each Endpoint of this Node */
  for (const auto & endpoint : node->mEpList) {
    if (MatterTranslator::mOcfFromMatter.find(endpoint.second->mDeviceTypes) != MatterTranslator::mOcfFromMatter.end()) {

      /* create VOD */
      const auto & deviceFromEndpointMapper = MatterTranslator::mOcfFromMatter[endpoint.second->mDeviceTypes];

      VerifyOrReturnValue(!deviceFromEndpointMapper.CreateVOD({ g_DestinationNodeId, endpoint.second->mEpId }, endpoint.second->mDeviceTypes, &deviceIndex),
          -1,
          OC_BRG_LOG("Creation of VOD corresponding to %lx:%d failed!", node->mNodeId, endpoint.second->mEpId);
          UNSET_ONGOING_COMMAND();
      );

      /*  OCF <- Matter */
      /*
       * store Device Index of the corresponding OCF VOD
       * - OCF Device Index <- { Matter NodeID, EndpointID }
       */
      endpoint.second->mOcfDeviceIndex = deviceIndex;

      /*  OCF -> Matter */
      /*
       * create new mapping info { OCF Device Index, { Matter NodeID, EndpointID } }
       * - OCF Device Index -> { Matter NodeID, EndpointID }
       */
      MatterTranslator::mMatterNodesByDeviceindex[deviceIndex] = { node->mNodeId, endpoint.second->mEpId };

      VerifyOrReturnValue(!_CreateResources(endpoint.second->mClusterList, deviceFromEndpointMapper, deviceIndex), -1);
    }
  }
  return 0;
}


/*
 * destroy OCF VOD for all EPs of target Node
 */
static int
_DeleteVOD(const NodeId & nodeId)
{
  /* remove { Matter Node ID, MatterNode } */
  map<NodeId, shared_ptr<MatterNode>>::iterator node;
  if ((node = MatterTranslator::mMatterNodesByNodeid.find(nodeId)) != MatterTranslator::mMatterNodesByNodeid.end()) {

#ifdef OC_BRG_DEBUG
    OC_BRG_LOG("before removing target node: 0x%lx", nodeId);
    OC_BRG_LOG("mMatterNodesByNodeId List:");
    for (const auto & i : MatterTranslator::mMatterNodesByNodeid) {
      i.second->print();
    }

    OC_BRG_LOG("mMatterNodesByDeviceindex List:");
    for (const auto & i : MatterTranslator::mMatterNodesByDeviceindex) {
      string vodMapping = { "[ OCF Device ID: " + to_string(i.first) + ", { Matter NodeID: " + to_string(i.second.first) +
          ", EndpointID: " + to_string(i.second.second) + " } ]"  };
      OC_BRG_LOG("%s", vodMapping.c_str());
    }

    OC_BRG_LOG("OCF Device List:");
    oc_bridge_print_device_list();
#endif

    /* remove all OCF Device info mapped to all EPs of this Node...
     * - { OCF device index, { Matter Node, Matter EP } } */
    for (const auto & ep : node->second->mEpList) {
      /* skip root node EP */
      if (!ep.first)
        continue;

      OC_BRG_LOG("Device Id of corresponding OCF Device: %ld", ep.second->mOcfDeviceIndex);
      /* remove info of mapped OCF Device */
      MatterTranslator::mMatterNodesByDeviceindex.erase(ep.second->mOcfDeviceIndex);
      /* ----- remove corresponding OCF VOD ----- */
      OC_BRG_LOG("removing VOD (%zd)...", ep.second->mOcfDeviceIndex);
      oc_bridge_delete_virtual_device(ep.second->mOcfDeviceIndex);
    }
    /* remove MatterNode cache entry */
    OC_BRG_LOG("removing Matter Node Cache (0x%lx)...", nodeId);
    MatterTranslator::mMatterNodesByNodeid.erase(nodeId);

#ifdef OC_BRG_DEBUG
    OC_BRG_LOG("after removing target node: 0x%lx", nodeId);
    OC_BRG_LOG("mMatterNodesByNodeId List:");
    for (const auto & i : MatterTranslator::mMatterNodesByNodeid) {
      i.second->print();
    }

    OC_BRG_LOG("mMatterNodesByDeviceindex List:");
    for (const auto & i : MatterTranslator::mMatterNodesByDeviceindex) {
      string vodMapping = { "[ OCF Device ID: " + to_string(i.first) + ", { Matter NodeID: " + to_string(i.second.first) +
          ", EndpointID: " + to_string(i.second.second) + " } ]"  };
      OC_BRG_LOG("%s", vodMapping.c_str());
    }

    OC_BRG_LOG("OCF Device List:");
    oc_bridge_print_device_list();
#endif

  }

  return 0;
}


/*
 * pair with Matter Device
 */
static int
Pairing(const char *parsedCommandJsonStr)
{
  OC_BRG_LOG("json string: \n%s", parsedCommandJsonStr);

  Json::Value jsonRoot;
  Json::CharReaderBuilder jsonBuilder;
  JSONCPP_STRING errMsg;

  SET_ONGOING_COMMAND(MatterTaskHandler::OnGoingCommand::ONGOING_COMMAND_PAIRING);

  /* deserialize json string */
  const unique_ptr<Json::CharReader> jsonReader(jsonBuilder.newCharReader());
  VerifyOrReturnValue(jsonReader->parse(parsedCommandJsonStr, parsedCommandJsonStr + strlen(parsedCommandJsonStr), &jsonRoot, &errMsg),
      -1,
      OC_BRG_LOG("command json parsing failed! : %s", errMsg.c_str());
      UNSET_ONGOING_COMMAND();
  );
  OC_BRG_LOG("json object: \n%s", jsonRoot.toStyledString().c_str());

  /* --------------------------------------------------------------------------
   * 0. launch thread which waits completion of pairing and creation of
   *    corresponding VOD..
   * -------------------------------------------------------------------------*/

  /* --------------------------------------------------------------------------
   * 1. pairing new node
   * -------------------------------------------------------------------------*/
  /* build pairing command string.. */
  string commandStr = "chip-tool " + jsonRoot[KEY_CMD][KEY_CMDSTR].asString() + string { " " } + jsonRoot[KEY_SUBCMD][KEY_CMDSTR].asString();
  for (const auto & param : jsonRoot[KEY_SUBCMD][KEY_VALUE]) {
    commandStr += (" " + param.asString());
  }
  OC_BRG_LOG("recombined command string: \"%s\"", commandStr.c_str());

  /* run "pairing" command */
  OC_BRG_LOG("trying to pair a matter node...");
  VerifyOrReturnValue(!_RunMatterCommand(commandStr), -1);

  /* --------------------------------------------------------------------------
   * 2. Do additional jobs for new Matter device pairing...
   * -------------------------------------------------------------------------*/
  if (!strcmp(jsonRoot[KEY_SUBCMD][KEY_CMDSTR].asString().c_str(), VALUE_SUBCMD_PAIRING_ONNETWORK)
      || !strcmp(jsonRoot[KEY_SUBCMD][KEY_CMDSTR].asString().c_str(), VALUE_SUBCMD_PAIRING_ONNETWORK_INSTANCE_NAME)) {
    /*
     * Do additional jobs for "Pairing" :
     *
     * Read BasicInformation, Descriptor of root node EP,
     * and read Descriptors of all other EPs of the Target Node.
     * - build MatterNode cache entry and its components...
     */

    /* --------------------------------------------------------------------------
     * 2.1 read BasicInformation cluster of root node EP
     * - create MatterNode instance and save basic information
     * -------------------------------------------------------------------------*/
    commandStr = "chip-tool basicinformation read-by-id 1,2,3,4,5,8,10 " + to_string(g_DestinationNodeId) + " 0";

    /* run "read basicinformation" command */
    OC_BRG_LOG("reading basicinformation of root node device of Node (%ld)...", g_DestinationNodeId);
    VerifyOrReturnValue(!_RunMatterCommand(commandStr, MatterTranslator::MatterCommandType::MATTER_READ, 7), -1);
    OC_BRG_LOG("found destination node ID: %ld", g_DestinationNodeId);

#ifdef OC_BRG_DEBUG
    OC_BRG_LOG("MatterNode (0x%lx) cache entry is added..", g_DestinationNodeId);
    for (const auto & node : MatterTranslator::mMatterNodesByNodeid) {
      node.second->print();
    }
#endif

    /* --------------------------------------------------------------------------
     * 2.2 read Descriptor cluster of root node EP (Device Type: 0x16)
     * - creates all endpoints other than root node
     * -------------------------------------------------------------------------*/
    /* read "PartsList" of root node device type.. */
    commandStr = "chip-tool descriptor read-by-id 3 " + to_string(g_DestinationNodeId) + " 0";

    /* run "read descriptor" command */
    OC_BRG_LOG("reading descriptor of root node device of Node (%ld)...", g_DestinationNodeId);
    VerifyOrReturnValue(!_RunMatterCommand(commandStr, MatterTranslator::MatterCommandType::MATTER_READ, 1), -1);
    OC_BRG_LOG("found destination node ID: %ld", g_DestinationNodeId);

#ifdef OC_BRG_DEBUG
    OC_BRG_LOG("EPs for MatterNode (0x%lx) are added..", g_DestinationNodeId);
    for (const auto & node : MatterTranslator::mMatterNodesByNodeid) {
      node.second->print();
    }
#endif

    /* --------------------------------------------------------------------------
     * 2.3 read Descriptor cluster of all other endpoints..
     * - configure Devicetype and clusters for each endpoint of this Node
     * -------------------------------------------------------------------------*/
    for (const auto & ep : MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mEpList) {
      if (ep.first != 0) {
        /* read "DeviceTypeLists" and "ServerList" of other EP.. */
        commandStr = "chip-tool descriptor read-by-id 0,1 " + to_string(g_DestinationNodeId) + " " + to_string(ep.first);

        /* run "read descriptor" command */
        OC_BRG_LOG("reading descriptor of EP (%d) of Node (%ld)...", ep.first, g_DestinationNodeId);
        VerifyOrReturnValue(!_RunMatterCommand(commandStr, MatterTranslator::MatterCommandType::MATTER_READ, 2), -1);
        OC_BRG_LOG("found destination node ID: %ld", g_DestinationNodeId);

#ifdef OC_BRG_DEBUG
        OC_BRG_LOG("Device Types and Cluster for each EP of MatterNode (0x%lx) are added..", g_DestinationNodeId);
        for (const auto & node : MatterTranslator::mMatterNodesByNodeid) {
          node.second->print();
        }
#endif
      }
    }

    /* --------------------------------------------------------------------------
     * 2.4 creates VODs corresponding to all normal endpoints..
     * - create VOD and Resources corresponding to each endpoint and clusters on it
     * -------------------------------------------------------------------------*/

    /*
     * 2.2. create and add VOD entries corresponding to the each EP (Device Type) entry
     * @OnResponse() of ReportCommand
     *
     * - store address of each corresponding EP (Device Type) entry in "VOD" (virtual_device_t)
     * - add Application Resources list to the corresponding "VOD"
     * - register GET/POST callbacks of these Application Resources when those Application Resources are created
     */
    VerifyOrReturnValue(!_CreateVOD(), -1);
  } else if (!strcmp(jsonRoot[KEY_SUBCMD][KEY_CMDSTR].asString().c_str(), VALUE_SUBCMD_PAIRING_UNPAIR)) {
    /*
     * Do additional jobs for "UnPairing" :
     * - Remove MatterNode cache entry and related mapping infos..
     */

    /* ----- remove target Node from list ----- */
    /* get target Node ID */
    OC_BRG_LOG("Node ID to be removed: 0x%x", stoi(jsonRoot[KEY_SUBCMD][KEY_VALUE][0].asString(), nullptr, 0));
    NodeId nodeId = stoi(jsonRoot[KEY_SUBCMD][KEY_VALUE][0].asString(), nullptr, 0);

    VerifyOrReturnValue(!_DeleteVOD(nodeId), -1);
  }

  UNSET_ONGOING_COMMAND();
  return 0;
}


/*---------------------------------------------------------------------------*/
/*
 *  common callback APIs that every translation plugin should implement
 */
/*---------------------------------------------------------------------------*/
static int
Retrieve(const char *parsed_command_json_str)
{
  OC_BRG_LOG("json string: %s", parsed_command_json_str);

  Json::Value jsonRoot;
  Json::CharReaderBuilder jsonBuilder;
  JSONCPP_STRING errMsg;

  /* 0. Mark new command is in progress from now on .. */
  SET_ONGOING_COMMAND(MatterTaskHandler::OnGoingCommand::ONGOING_COMMAND_RETRIEVE);

  const unique_ptr<Json::CharReader> jsonReader(jsonBuilder.newCharReader());
  VerifyOrReturnValue(jsonReader->parse(parsed_command_json_str, parsed_command_json_str + strlen(parsed_command_json_str), &jsonRoot, &errMsg),
      -1,
      OC_BRG_LOG("command json parsing failed! : %s", errMsg.c_str());
      UNSET_ONGOING_COMMAND();
  );

  OC_BRG_LOG("cmd: \"%s\", option: \"%s %s\", econame: \"%s\"",
      jsonRoot[KEY_CMD][KEY_CMDSTR].asString().c_str(),
      jsonRoot[KEY_OPTIONS][0][KEY_CMDSTR].asString().c_str(),
      jsonRoot[KEY_OPTIONS][0][KEY_VALUE].asString().c_str(),
      jsonRoot[KEY_ECONAME].asString().c_str());


  /* --------------------------------------------------------------------------
   * 1. retrieving cluster attributes...
   * -------------------------------------------------------------------------*/

  /* build command string
   * format : <cluster_name> read-by-id <attribute-ids> <destination-id> <endpoint-ids> */

  /* ----- find Device ----- */
  /* extract target device ID, target Resource path */
  auto targetPath = MatterTranslator::SplitURI(jsonRoot[KEY_OPTIONS][0][KEY_VALUE].asString());
  OC_BRG_LOG("extracted Devide ID: \"%s\", Resource path: \"%s\"", targetPath.first.c_str(), targetPath.second.c_str());

  oc_uuid_t di;
  oc_str_to_uuid(targetPath.first.c_str(), &di);

  size_t deviceIndex;
  VerifyOrReturnValue(!oc_core_get_device_index(di, &deviceIndex),
      -1,
      UNSET_ONGOING_COMMAND()
  );

#ifdef OC_BRG_DEBUG
  oc_device_info_t *ocfDevice = oc_core_get_device_info(deviceIndex);
  OC_BRG_LOG("found device's name: %s", oc_string(ocfDevice->name));
#endif

  /* ----- get Device Types ----- */
  const oc_resource_t *deviceResource = oc_core_get_resource_by_uri_v1(string{"/oic/d"}.c_str(), string{"/oic/d"}.size(), deviceIndex);
  VerifyOrReturnValue(deviceResource,
      -1,
      UNSET_ONGOING_COMMAND()
  );

  /* convert oc_string_array_t into std::set */
  set<string, std::less<>> deviceTypes = MatterTranslator::ConvertStrarrayToSet(deviceResource->types);

#ifdef OC_BRG_DEBUG
  for (const auto & i : deviceTypes) {
    OC_BRG_LOG("original device type: %s", i.c_str());
  }
#endif

  /* remove other extra device types.. */
  for (auto rt = deviceTypes.begin() ; rt != deviceTypes.end(); ) {
    if (*rt == "oic.d.virtual" || *rt == "oic.wk.d") {
      rt = deviceTypes.erase(rt);
    } else {
      rt++;
    }
  }

#ifdef OC_BRG_DEBUG
  for (const auto & i : deviceTypes) {
    OC_BRG_LOG("pure device type: %s", i.c_str());
  }
#endif

  /* ----- Node Id, Endpoint Id ----- */
  VerifyOrReturnValue(MatterTranslator::mMatterNodesByDeviceindex.find(deviceIndex) != MatterTranslator::mMatterNodesByDeviceindex.end(),
      -1,
      OC_BRG_LOG("can't find Target matter Node for device (%zd)!", deviceIndex);
      UNSET_ONGOING_COMMAND()
  );
  auto matterNode = MatterTranslator::mMatterNodesByDeviceindex[deviceIndex];

  /* ----- Get Cluster name ----- */
  const oc_resource_t *targetResource = oc_ri_get_app_resource_by_uri(targetPath.second.c_str(), targetPath.second.size(), deviceIndex);
  VerifyOrReturnValue(targetResource, -1,
      OC_BRG_LOG("can't find Target Resource for \"%s\"!", targetPath.second.c_str());
      UNSET_ONGOING_COMMAND()
  );

  auto resourceTypes = MatterTranslator::ConvertStrarrayToSet(targetResource->types);
  VerifyOrReturnValue((MatterTranslator::mOcfToMatter.find(deviceTypes) != MatterTranslator::mOcfToMatter.end()) &&
      (MatterTranslator::mOcfToMatter[deviceTypes].R2CMapper().find(*resourceTypes.begin()) != MatterTranslator::mOcfToMatter[deviceTypes].R2CMapper().end()),
      -1,
      OC_BRG_ERR("something is wrong! there is no OCF => Matter Mapper for %s of %s!", resourceTypes.begin()->c_str(), deviceTypes.begin()->c_str());
      UNSET_ONGOING_COMMAND()
  );

  auto resourceToClusterMapper = MatterTranslator::mOcfToMatter[deviceTypes].R2CMapper()[*resourceTypes.begin()];
  auto clusterName = resourceToClusterMapper.ClusterName();

  /* ----- build attributes list ----- */
  /*
   * build matter attribute id list in jsonRoot
   * - { { <attributeId1>: 0 }, { <attributeId2>: 0 }, ... }
   */
  ResourceToClusterMapper::Reset(); /* clear jsonRoot before build attribute list... */
  for (const auto & propertyToAttributeMapper : resourceToClusterMapper.P2AMapper()) {
    propertyToAttributeMapper.second->Translate(MatterTranslator::TransactionTranslationMode::OCF_TO_MATTER_RETRIEVE);
  }

  /* ----- build command string ----- */
  auto attrIdList = ResourceToClusterMapper::JsonRoot().getMemberNames();
  string commandStr { "chip-tool " + clusterName + " read-by-id " +
    [](auto attrIds) { string r {attrIds[0]}; for (size_t i=1; i<attrIds.size(); i++) { r += (","+attrIds[i]); } return r; }(attrIdList)
    + " " + to_string(matterNode.first) + " " + to_string(matterNode.second) };
  OC_BRG_LOG("final command str: \"%s\"", commandStr.c_str());

  /* ----- Fire Command ! ----- */
  /* reset jsonRoot to collect new response results... */
  ResourceFromClusterMapper::Reset();
  ResourceFromClusterMapper::JsonRoot()[MatterTranslator::mResultStatus] = OC_STATUS_OK;
  VerifyOrReturnValue(!_RunMatterCommand(commandStr, MatterTranslator::MatterCommandType::MATTER_READ, (int)attrIdList.size()), -1);

  /* print result... */
  printf("retrieve result: \n%s", ResourceFromClusterMapper::JsonRoot().toStyledString().c_str());

  UNSET_ONGOING_COMMAND();
  return 0;
}


static int
Update(const char *parsed_command_json_str)
{
  OC_BRG_LOG("json string: %s", parsed_command_json_str);

  Json::Value jsonRoot;
  Json::CharReaderBuilder jsonBuilder;
  JSONCPP_STRING errMsg;

  /* 0. Mark new command is in progress from now on .. */
  SET_ONGOING_COMMAND(MatterTaskHandler::OnGoingCommand::ONGOING_COMMAND_UPDATE);

  const unique_ptr<Json::CharReader> jsonReader(jsonBuilder.newCharReader());
  VerifyOrReturnValue(jsonReader->parse(parsed_command_json_str, parsed_command_json_str + strlen(parsed_command_json_str), &jsonRoot, &errMsg),
      -1,
      OC_BRG_LOG("command json parsing failed! : %s", errMsg.c_str());
      UNSET_ONGOING_COMMAND();
  );

  OC_BRG_LOG("cmd: \"%s\", option: \"%s: %s\", \"%s: %s\", econame: \"%s\"",
      jsonRoot[KEY_CMD][KEY_CMDSTR].asString().c_str(),
      jsonRoot[KEY_OPTIONS][0][KEY_CMDSTR].asString().c_str(),
      jsonRoot[KEY_OPTIONS][0][KEY_VALUE].asString().c_str(),
      jsonRoot[KEY_OPTIONS][1][KEY_CMDSTR].asString().c_str(),
      jsonRoot[KEY_OPTIONS][1][KEY_VALUE].toStyledString().c_str(),
      jsonRoot[KEY_ECONAME].asString().c_str());


  /* --------------------------------------------------------------------------
   * 1. retrieving cluster attributes...
   * -------------------------------------------------------------------------*/

  /* build command string
   * format : <cluster_name> write-by-id <attribute-ids> <attribute-values> <destination-id> <endpoint-ids> */

  /* ----- find Device ----- */
  /* extract target device ID, target Resource path */
  auto targetPath = MatterTranslator::SplitURI(jsonRoot[KEY_OPTIONS][0][KEY_VALUE].asString());
  OC_BRG_LOG("extracted Devide ID: \"%s\", Resource path: \"%s\"", targetPath.first.c_str(), targetPath.second.c_str());

  oc_uuid_t di;
  oc_str_to_uuid(targetPath.first.c_str(), &di);

  size_t deviceIndex;
  VerifyOrReturnValue(!oc_core_get_device_index(di, &deviceIndex),
      -1,
      UNSET_ONGOING_COMMAND()
  );

#ifdef OC_BRG_DEBUG
  oc_device_info_t *ocfDevice = oc_core_get_device_info(deviceIndex);
  OC_BRG_LOG("found device's name: %s", oc_string(ocfDevice->name));
#endif

  /* ----- get Device Types ----- */
  const oc_resource_t *deviceResource = oc_core_get_resource_by_uri_v1(string{"/oic/d"}.c_str(), string{"/oic/d"}.size(), deviceIndex);
  VerifyOrReturnValue(deviceResource,
      -1,
      OC_BRG_LOG("can't find Device Resource for \"%s\"!", targetPath.first.c_str());
      UNSET_ONGOING_COMMAND();
  );

  /* convert oc_string_array_t into std::set */
  set<string, std::less<>> deviceTypes = MatterTranslator::ConvertStrarrayToSet(deviceResource->types);

#ifdef OC_BRG_DEBUG
  for (const auto & i : deviceTypes) {
    OC_BRG_LOG("original device type: %s", i.c_str());
  }
#endif

  /* remove other extra device types.. */
  for (auto rt = deviceTypes.begin() ; rt != deviceTypes.end(); ) {
    if (*rt == "oic.d.virtual" || *rt == "oic.wk.d") {
      rt = deviceTypes.erase(rt);
    } else {
      rt++;
    }
  }

#ifdef OC_BRG_DEBUG
  for (const auto & i : deviceTypes) {
    OC_BRG_LOG("pure device type: %s", i.c_str());
  }
#endif

  /* ----- Node Id, Endpoint Id ----- */
  VerifyOrReturnValue(MatterTranslator::mMatterNodesByDeviceindex.find(deviceIndex) != MatterTranslator::mMatterNodesByDeviceindex.end(),
      -1,
      OC_BRG_ERR("something is wrong! there is no MatterNode mapping for device (%zd)!", deviceIndex);
      UNSET_ONGOING_COMMAND();
  );
  auto matterNode = MatterTranslator::mMatterNodesByDeviceindex[deviceIndex];

  /* ----- Get Cluster name ----- */
  const oc_resource_t *targetResource = oc_ri_get_app_resource_by_uri(targetPath.second.c_str(), targetPath.second.size(), deviceIndex);
  VerifyOrReturnValue(targetResource,
      -1,
      OC_BRG_LOG("can't find Target Resource for \"%s\"!", targetPath.second.c_str());
      UNSET_ONGOING_COMMAND();
  );
  auto resourceTypes = MatterTranslator::ConvertStrarrayToSet(targetResource->types);

  VerifyOrReturnValue((MatterTranslator::mOcfToMatter.find(deviceTypes) != MatterTranslator::mOcfToMatter.end()) &&
      (MatterTranslator::mOcfToMatter[deviceTypes].R2CMapper().find(*resourceTypes.begin()) != MatterTranslator::mOcfToMatter[deviceTypes].R2CMapper().end()),
      -1,
      OC_BRG_ERR("something is wrong! there is no OCF => Matter Mapper for %s of %s!", resourceTypes.begin()->c_str(), deviceTypes.begin()->c_str());
      UNSET_ONGOING_COMMAND();
  );
  auto resourceToClusterMapper = MatterTranslator::mOcfToMatter[deviceTypes].R2CMapper()[*resourceTypes.begin()];
  auto clusterName = resourceToClusterMapper.ClusterName();

  /* ----- attributes list ----- */
  /**
   * build matter {attribute id, value } list in jsonRoot
   * - { { <attributeId1>: <updateValue1> }, { <attributeId2>: <updateValue2> }, ... }
   *
   * or
   *
   * Build commandId and payload
   * - { { <commandId>, <payload> } }
   */
  ResourceToClusterMapper::Reset(); /* clear jsonRoot before build attribute list... */

  /* get Property name list from user input... and translate them! */
  auto propertyList = jsonRoot[KEY_OPTIONS][1][KEY_VALUE].getMemberNames();
  for (const auto & propertyName : propertyList) {
    VerifyOrDo(resourceToClusterMapper.P2AMapper().find(propertyName) == resourceToClusterMapper.P2AMapper().end(),
        resourceToClusterMapper.P2AMapper()[propertyName]->Translate(
            MatterTranslator::TransactionTranslationMode::OCF_TO_MATTER_UPDATE,
            jsonRoot[KEY_OPTIONS][1][KEY_VALUE][propertyName.c_str()])
    );
  }

  /* ----- build command string ----- */
  auto attrOrCommandIdList = ResourceToClusterMapper::JsonRoot().getMemberNames();

  string commandStr { "chip-tool " };
  switch (ResourceToClusterMapper::JsonRoot()[MatterTranslator::mFinalOcfToMatterMode].asInt()) {
  case (int)ResourceToClusterMapper::PropertyTranslationMode::UPDATE_PROPERTY_TO_ATTRIBUTE:
    commandStr = commandStr + clusterName + " write-by-id "
      + [](const auto &attrIds) { string r {attrIds[0]}; for (size_t i=1; i<attrIds.size(); i++) { r += (","+attrIds[i]); } return r; }(attrOrCommandIdList)
      + " "
      + [&](const auto &jsonValue) { string r {jsonValue[attrOrCommandIdList[0]].asString()}; for (size_t i=1; i<attrOrCommandIdList.size(); i++) { r += (";"+jsonValue[attrOrCommandIdList[i]].asString()); } return r; }(ResourceToClusterMapper::JsonRoot())
      + " "
      + to_string(matterNode.first) + " " + to_string(matterNode.second);
    OC_BRG_LOG("final command str: \"%s\"", commandStr.c_str());
    break;
  case (int)ResourceToClusterMapper::PropertyTranslationMode::UPDATE_PROPERTY_TO_COMMAND:
  case (int)ResourceToClusterMapper::PropertyTranslationMode::UPDATE_PROPERTY_TO_COMMAND_WITH_PAYLOAD:
    commandStr = commandStr + clusterName + " command-by-id "
      + attrOrCommandIdList[0]
      + " "
      + ResourceToClusterMapper::JsonRoot()[attrOrCommandIdList[0]].asString()
      + " "
      + to_string(matterNode.first) + " " + to_string(matterNode.second);
    OC_BRG_LOG("final command str: \"%s\"", commandStr.c_str());
    break;
  default:
    /* if jsonRoot[OCF_TO_MATTER_MODE] is empty,
     * it means that property translation is not supported.. */
    OC_BRG_ERR("Some property is READ-ONLY, or its translation is not supported!");
    UNSET_ONGOING_COMMAND();
    return -1;
    break;
  }

  /* ----- Fire Command ! ----- */
  /* reset jsonRoot to collect new response results... */
  ResourceFromClusterMapper::Reset();
  ResourceFromClusterMapper::JsonRoot()[MatterTranslator::mResultStatus] = OC_STATUS_OK;
  VerifyOrReturnValue(!_RunMatterCommand(commandStr), -1);

  /* print result... */
  printf("retrieve result: \n%s", ResourceFromClusterMapper::JsonRoot().toStyledString().c_str());
  UNSET_ONGOING_COMMAND();
  return 0;
}


/*
 * create cli_command_t for new ecosystem-specific aommand
 */
static cli_command_t *
_NewEcosystemCommand(const char *cmd_str, cb_ecosystem_command_t callback)
{
  cli_command_t *cliCommandItem;

  cliCommandItem = (cli_command_t *)oc_memb_alloc(&g_cliCommandInstanceMemb);
  oc_new_string(&cliCommandItem->cmd_str, cmd_str, strlen(cmd_str));
  cliCommandItem->func = callback;

  return cliCommandItem;
}


/*
 * free cli_command_t for an ecosystem-specific aommand
 */
static void
_FreeEcosystemCommand(cli_command_t *item)
{
  oc_free_string(&item->cmd_str);
  oc_memb_free(&g_cliCommandInstanceMemb, item);

  return;
}


/*
 * @brief initialize plugin
 * @param cli_commandset_list ecosystem-specific commandset list to which
 *        commands provided by this plugin will be added.
 * @return 0: success, <0: failure
 */
int
InitPlugin(ecosystem_cli_commandset_t *cliCommandset)
{
  int tokenc;
  char **tokenv;
  cli_command_t *cliCommandItem;

  OC_BRG_LOG("init plugin...!");

  /* ----- 1. register callbacks for ecosystem-specific commands ----- */
  /* econame */
  oc_new_string(&cliCommandset->econame, "matter", strlen("matter"));

  /* commond commands */
  cliCommandset->retrieve = Retrieve;
  cliCommandset->update = Update;

  /* ecosystem-specific commands */
  cliCommandItem = _NewEcosystemCommand("discover", Discover);
  oc_list_add(cliCommandset->eco_commands, cliCommandItem);
  cliCommandItem = _NewEcosystemCommand("pairing", Pairing);
  oc_list_add(cliCommandset->eco_commands, cliCommandItem);

  /* ----- 2. register matter command handlers ----- */
  RegisterMatterCommand();

  /* ----- 3. initiate interactive matter client ----- */
  /* run matter client */
  /* build command string */
  string commandStr { "chip-tool interactive start" };

  /* fire command */
  tokenv = MatterTranslator::ConvertStrToTokenArray(commandStr, &tokenc);
  RunMatterCommand(tokenc, tokenv, Command::ClientInitState::COMMAND_INTERACTIVE_INIT);
  MatterTranslator::FreeTokenArray(tokenv, tokenc);

  /* initiate Matter Translator */
  MatterTranslator::Init("ocf.2.2.6", "ocf.1.1.0");

  return 0;
}


/*
 * @brief shutdown plugin
 * @param cli_commandset_list ecosystem-specific commandset list from which
 *        commands provided by this plugin will be removed.
 * @return 0: success, <0: failure
 */
int
ShutdownPlugin(ecosystem_cli_commandset_t *cli_commandset)
{
  int tokenc;
  char **tokenv;
  string commandStr;
  cli_command_t *cli_command_item;
  cli_command_t *t;

  /* ----- 1. free matter specific command set ----- */
  /* free ecosystem-specific commands */
  cli_command_item = (cli_command_t *)oc_list_head(cli_commandset->eco_commands);

  while (cli_command_item) {
    t = cli_command_item;
    cli_command_item = cli_command_item->next;

    _FreeEcosystemCommand(t);
  }

  /* free econame */
  oc_free_string(&cli_commandset->econame);

  /* ----- 2. shutdown matter translator ----- */
  /*
   * TODO4ME <2023/12/17> shutdown_plugin() : make it save all related information to storage..
   * and restore them when this module is reloaded..
   */
  MatterTranslator::Shutdown();

  /* ----- 3. shutdown Matter client ----- */
  /* clear storage */
#if 0
  commandStr = { "chip-tool storage clear-all" };
  tokenv = MatterTranslator::ConvertStrToTokenArray(commandStr, &tokenc);
  run_matter_command(tokenc, tokenv);
  MatterTranslator::FreeTokenArray(tokenv, tokenc);
#endif

  /* shutdown interactive client */
  commandStr = { "chip-tool interactive stop" };
  tokenv = MatterTranslator::ConvertStrToTokenArray(commandStr, &tokenc);
  RunMatterCommand(tokenc, tokenv, Command::ClientInitState::COMMAND_INTERACTIVE_SHUTDOWN);
  MatterTranslator::FreeTokenArray(tokenv, tokenc);

  /* unregister matter command handlers */
  UnregisterMatterCommand();

  return 0;
}


/* --------------------------------------------------------------------------
 * Iotivity-lite Callbacks for VOD Resources
 * -------------------------------------------------------------------------*/
static void _Json2Cbor(CborEncoder *parent, const string & key, const Json::Value & value);

/*
 * convert json object to cbor object
 */
static void
_Json2CborObjArray(CborEncoder *parent, const Json::Value & value)
{
  /* recurse objects of array... */
  for (const auto & obj : value) {

    /* open new object for each item of object array */
    CborEncoder obj_map;
    memset(&obj_map, 0, sizeof(obj_map));
    g_err |= oc_rep_encoder_create_map(parent, &obj_map, CborIndefiniteLength);

    /* build payload per each object... */
    auto objKeyList = obj.getMemberNames();
    for (const auto & objKey : objKeyList) {
      _Json2Cbor(&obj_map, objKey, obj[objKey]);
    }

    /* close new object */
    g_err |= oc_rep_encoder_close_container(parent, &obj_map);
  }

  return;
}


/*
 * convert json array to cbor array object
 */
static void
_Json2CborArray(CborEncoder *parent, const string & key, const Json::Value & value)
{
  CborEncoder child;

  /* set key name */
  g_err |= oc_rep_encode_text_string(parent, key.c_str(), key.length());

  /* open new array object */
  memset(&child, 0, sizeof(child));
  g_err |= oc_rep_encoder_create_array(parent, &child, CborIndefiniteLength);

  if (!value.empty()) {
    if (value[0].isString()) {
      /* string array */
      for (const auto & item : value) {
        g_err |= oc_rep_encode_text_string(&child, item.asString().c_str(), item.asString().length());
      }
    } else if (value[0].isBool()) {
      /* bool array */
      for (const auto & item : value) {
        g_err |= oc_rep_encode_boolean(&child, item.asBool());
      }
    } else if (value[0].isDouble()) {
      /* double array */
      for (const auto & item : value) {
        g_err |= oc_rep_encode_double(&child, item.asDouble());
      }
    } else if (value[0].isInt()) {
      /* int array */
      for (const auto & item : value) {
        g_err |= oc_rep_encode_int(&child, item.asInt());
      }
    } else if (value[0].isObject()) {
      /* object array */
      /* recurse remaining objects... */
      _Json2CborObjArray(&child, value);
    }
  }

  /* close new array object */
  g_err |= oc_rep_encoder_close_container(parent, &child);
}


/*
 * convert json value to cbor object
 */
static void
_Json2Cbor(CborEncoder *parent, const string & key, const Json::Value & value)
{
  if (value.isArray()) {
    _Json2CborArray(parent, key, value);
  } else if (value.isBool()) {
    g_err |= oc_rep_encode_text_string(parent, key.c_str(), key.length());
    g_err |= oc_rep_encode_boolean(parent, value.asBool());
  } else if (value.isInt()) {
    g_err |= oc_rep_encode_text_string(parent, key.c_str(), key.length());
    g_err |= oc_rep_encode_int(parent, value.asInt());
  } else if (value.isDouble()) {
    g_err |= oc_rep_encode_text_string(parent, key.c_str(), key.length());
    g_err |= oc_rep_encode_double(parent, value.asDouble());
  } else if (value.isObject()) {
    CborEncoder child;
    g_err |= oc_rep_encode_text_string(parent, key.c_str(), key.length());

    memset(&child, 0, sizeof(child));
    g_err |= oc_rep_encoder_create_map(parent, &child, CborIndefiniteLength);

    auto objKeyList = value.getMemberNames();
    for (const auto & objKey : objKeyList) {
      _Json2Cbor(&child, objKey, value[objKey]);
    }

    g_err |= oc_rep_encoder_close_container(parent, &child);
  } else if (value.isString()) {
    g_err |= oc_rep_encode_text_string(parent, key.c_str(), key.length());
    g_err |= oc_rep_encode_text_string(parent, value.asString().c_str(), value.asString().length());
  }
  return;
}


/*
 * convert cbor object to json
 */
static void
_Cbor2Json(oc_rep_t *rep, Json::Value & jsonObj)
{
  while (rep) {
    switch (rep->type) {
    case OC_REP_NIL:
      break;
    case OC_REP_INT:
      jsonObj[string{oc_string(rep->name)}] = rep->value.integer;
      break;
    case OC_REP_DOUBLE:
      jsonObj[string{oc_string(rep->name)}] = rep->value.double_p;
      break;
    case OC_REP_BOOL:
      jsonObj[string{oc_string(rep->name)}] = rep->value.boolean;
      break;
    case OC_REP_BYTE_STRING_ARRAY:
    case OC_REP_STRING_ARRAY:
      for (int i = 0; i < (int)oc_string_array_get_allocated_size(rep->value.array); i++) {
        jsonObj[string{oc_string(rep->name)}][i] = oc_string_array_get_item(rep->value.array, i);
      }
      break;

    case OC_REP_BOOL_ARRAY: {
      bool *boolArray;
      size_t boolArraySize;
      int i=0;
      if (oc_rep_get_bool_array(rep, oc_string(rep->name), &boolArray, &boolArraySize)) {
        jsonObj[string{oc_string(rep->name)}][i] = boolArray[i];
      }
      break;
    }

    case OC_REP_DOUBLE_ARRAY: {
      double *doubleArray;
      size_t doubleArraySize;
      int i=0;
      if (oc_rep_get_double_array(rep, oc_string(rep->name), &doubleArray, &doubleArraySize)) {
        jsonObj[string{oc_string(rep->name)}][i] = doubleArray[i];
      }
      break;
    }

    case OC_REP_INT_ARRAY: {
      double *intArray;
      size_t intArraySize;
      int i=0;
      if (oc_rep_get_double_array(rep, oc_string(rep->name), &intArray, &intArraySize)) {
        jsonObj[string{oc_string(rep->name)}][i] = intArray[i];
      }
      break;
    }

    case OC_REP_BYTE_STRING:
    case OC_REP_STRING:
      jsonObj[string{oc_string(rep->name)}] = oc_string(rep->value.string);
      break;

    case OC_REP_OBJECT: {
        _Cbor2Json(rep->value.object, jsonObj[string{oc_string(rep->name)}]);
      break;
    }

    case OC_REP_OBJECT_ARRAY: {
      oc_rep_t *obj_rep = rep->value.object_array;
      int i = 0;
      while (obj_rep) {
        _Cbor2Json(obj_rep->value.object, jsonObj[string{oc_string(rep->name)}][i]);
        obj_rep = obj_rep->next;
        i++;
      }
      break;
    }

    default:
      break;
    }

    rep = rep->next;
  } /* while(rep) */
}


/*
 * remove all VODs mapped to Matter EPs
 */
void ResetVODs()
{
  Json::Value jsonRoot;
  /*
    {
      "cmd" :
      {
        "cmd_str" : "pairing",
        "value" : null
      },
      "econame" : "matter",
      "options" : [],
      "subcmd" :
      {
        "cmd_str" : "unpair",
        "value" :
        [
          "0x10"
        ]
      }
    }
  */
  jsonRoot["cmd"]["cmd_str"] = "pairing";
  jsonRoot["cmd"]["value"] = Json::nullValue;
  jsonRoot["subcmd"]["cmd_str"] = "unpair";
  jsonRoot["options"] = Json::nullValue;
  jsonRoot["econame"] = "matter";

  auto it = MatterTranslator::mMatterNodesByNodeid.begin();
  while (it != MatterTranslator::mMatterNodesByNodeid.end()) {
    jsonRoot["subcmd"]["value"][0] = to_string(it->first);
    OC_BRG_LOG("command string: %s", jsonRoot.toStyledString().c_str());
    VerifyOrReturn(!Pairing(jsonRoot.toStyledString().c_str()),
        OC_BRG_ERR("pairing for %s failed!", jsonRoot.toStyledString().c_str());
    );

    /*
     * unpair operation of pairing() function removes corresponding item
     * from MatterTranslator::mMatterNodesByNodeid.
     * so use below codes to pick next item to be removed...
     */
    it = MatterTranslator::mMatterNodesByNodeid.begin();
  }
}


/* for RETRIEVE */
void VODResourceGetHandler(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)user_data;
  Json::Value jsonRoot;

  /* 0. build json string for this get request */
  /*
   {
    "cmd": {
      "cmd_str": "retrieve",
      "value": null
    },
    "subcmd": {
      "cmd_str": null,
      "value": null
    },
    "options": [
      {
      "cmd_str": "-name",
      "value": "fd2f232e-267c-4d9c-7e9f-90119724a499/Thermostat/Temperature"
      }
    ],
    "econame": "matter"
  }
  */

  char diStr[OC_UUID_LEN];

  jsonRoot["cmd"]["cmd_str"] = "retrieve";
  jsonRoot["cmd"]["value"] = Json::nullValue;

  jsonRoot["subcmd"]["cmd_str"] = Json::nullValue;
  jsonRoot["subcmd"]["value"] = Json::nullValue;

  jsonRoot["options"][0]["cmd_str"] = "-name";

  /* extract device ID, target Resource URI */
  oc_uuid_to_str(oc_core_get_device_id(request->resource->device), diStr, OC_UUID_LEN);
  jsonRoot["options"][0]["value"] = string {diStr} + /*"/" +*/ oc_string(request->resource->uri);

  jsonRoot["econame"] = "matter";

  OC_BRG_LOG("built command json: \n%s", jsonRoot.toStyledString().c_str());

  /* 1. Call retrieve() */
  VerifyOrReturn(!Retrieve(jsonRoot.toStyledString().c_str()),
      OC_BRG_ERR("retrieve for %s failed!", jsonRoot.toStyledString().c_str());
  );

  /* 2. build Response payload based on retrieve result.. */
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    /* fall through */
  case OC_IF_RW: {
    auto propertyNameList = ResourceFromClusterMapper::JsonRoot().getMemberNames();
    for (const auto & propertyName : propertyNameList) {
      if (propertyName == MatterTranslator::mResultStatus) continue;
      _Json2Cbor(&root_map, propertyName, ResourceFromClusterMapper::JsonRoot()[propertyName]);
    }
    break;
  }

  default:
    break;
  }
  oc_rep_end_root_object();

  oc_send_response(request, (oc_status_t)ResourceFromClusterMapper::JsonRoot()[MatterTranslator::mResultStatus].asUInt());
}


/* for UPDATE */
void VODResourcePostHandler(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)user_data;
  (void)iface_mask;

  Json::Value jsonRoot;
  Json::Value jsonPayload;

  char diStr[OC_UUID_LEN];

  /* 0. build json string for this update request */
  /* update */
  jsonRoot["cmd"]["cmd_str"] = "update";
  jsonRoot["cmd"]["value"] = Json::nullValue;
  jsonRoot["subcmd"]["cmd_str"] = Json::nullValue;
  jsonRoot["subcmd"]["value"] = Json::nullValue;

  /* update -name */
  jsonRoot["options"][0]["cmd_str"] = "-name";

  /* update -name <di>/<uri> */
  /* extract device ID, target Resource URI */
  oc_uuid_to_str(oc_core_get_device_id(request->resource->device), diStr, OC_UUID_LEN);
  jsonRoot["options"][0]["value"] = string {diStr} + oc_string(request->resource->uri);

  /* update -name <di>/<uri> -value { ... } */
  jsonRoot["options"][1]["cmd_str"] = "-value";

  /* build update payload : oc_rep_t => json stream */
  _Cbor2Json(request->request_payload, jsonPayload);
  jsonRoot["options"][1]["value"] = jsonPayload;

  /* command econame */
  jsonRoot["econame"] = "matter";

  OC_BRG_LOG("built command json: \n%s", jsonRoot.toStyledString().c_str());

  /* 1. Call retrieve() */
  VerifyOrReturn(!Update(jsonRoot.toStyledString().c_str()),
      OC_BRG_ERR("update for %s failed!", jsonRoot.toStyledString().c_str());
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
  );

  /* 2. Send Response */
  oc_send_response(request, (oc_status_t)ResourceFromClusterMapper::JsonRoot()[MatterTranslator::mResultStatus].asUInt());
}





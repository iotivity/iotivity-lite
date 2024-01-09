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


#include <commands/common/DeviceScanner.h>
#include <commands/common/RemoteDataModelLogger.h>
#include <commands/common/DeviceScanner.h>
#include <commands/pairing/PairingCommand.h>

#include <lib/support/BytesToHex.h>
#include <lib/support/jsontlv/TlvJson.h>
#include <lib/support/logging/CHIPLogging.h>
#include <lib/core/CHIPSafeCasts.h>

#include <platform/PlatformManager.h>
#include <controller/ExampleOperationalCredentialsIssuer.h>
#include <crypto/CHIPCryptoPAL.h>
#include <protocols/secure_channel/PASESession.h>

#include <setup_payload/ManualSetupPayloadParser.h>
#include <setup_payload/QRCodeSetupPayloadParser.h>

#include "bridge_interface.h"
#include "matter_client.h"
#include "MatterTaskHandler.h"

#include <fstream>
#include <json/json.h>

using namespace ::std;


void
MatterTaskHandler::OnPairingCommandComplete(NodeId nodeId)
{
  OC_BRG_LOG("==========> %s is successful! (NodeID: %lx) <==========", __func__ , nodeId);
  g_DestinationNodeId = nodeId;

  /*
   * notify "bridge_interface" that pairing and related jobs has been done..
   */
  NOTIFY_TASK_IS_COMPLETED();
  return;
}


static void
_CreateMatterNode(const chip::app::ConcreteDataAttributePath & path, const Json::Value & value)
{
  /* create new MatterNode, if it has not been created.. */
  if (MatterTranslator::mMatterNodesByNodeid.find(g_DestinationNodeId) == MatterTranslator::mMatterNodesByNodeid.end()) {
    OC_BRG_LOG("no MatterNode for 0x%lx has not been created yet, so create new one..", g_DestinationNodeId);
    MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId] = make_shared<MatterNode>(g_DestinationNodeId);
  }

  /* create new Endpoint, if it has not been created.. */
  if (MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mEpList.find(path.mEndpointId)
      == MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mEpList.end()) {
    OC_BRG_LOG("no Endpoint 0x%x for MatterNode (0x%lx) has not been created yet, so create new one..",
        path.mEndpointId, g_DestinationNodeId);
    MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mEpList[path.mEndpointId] =
        make_shared<MatterEndpoint>(path.mEndpointId, g_DestinationNodeId);
    if (path.mEndpointId == 0) {
      /* device type : root node */
      MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mEpList[path.mEndpointId]->mDeviceTypes.insert(0x16);
    }
  }

  if (value["attributeId"].asUInt() == 1) {
    /* VendorName */
    OC_BRG_LOG("vendor name: \"%s\"", value["value"].asString().c_str());
    MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mVendorName = value["value"].asString();
  } else if (value["attributeId"].asUInt() == 2) {
    /* VendorId */
    OC_BRG_LOG("vendor id: %x", value["value"].asInt());
    MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mVendorId = (uint16_t)value["value"].asUInt();
  } else if (value["attributeId"].asUInt() == 3) {
    /* ProductName */
    OC_BRG_LOG("Product Name: \"%s\"", value["value"].asString().c_str());
    MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mProductName = value["value"].asString();
  } else if (value["attributeId"].asUInt() == 4) {
    /* ProductID */
    OC_BRG_LOG("product id: %x", value["value"].asInt());
    MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mProductId = (uint16_t)value["value"].asUInt();
  } else if (value["attributeId"].asUInt() == 5) {
    /* NodeLabel */
    OC_BRG_LOG("Node Label: %s", value["value"].asString().c_str());
    MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mNodeLabel = value["value"].asString();
  } else if (value["attributeId"].asUInt() == 8) {
    /* HardwareVersionString */
    OC_BRG_LOG("Hardware version string: \"%s\"", value["value"].asString().c_str());
    MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mHwVerStr = value["value"].asString();
  } else if (value["attributeId"].asUInt() == 10) {
    /* SoftwareVersionString */
    OC_BRG_LOG("Software version string: \"%s\"", value["value"].asString().c_str());
    MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mSwVerStr = value["value"].asString();
  }

  return;
}


static void
_CreateMatterEP(const chip::app::ConcreteDataAttributePath & path, const Json::Value & value)
{
  /* ----- 2. Read Descriptor cluster of EP 0 to get all Endpoint list of this target Node ----- */
  if (path.mEndpointId == 0) {
    /*
     * EP id 0 : root node device type
     * - store all other device types of this Node
     */
    if (value["attributeId"].asUInt() == 3) {
      /* PartsList */
      for (const auto & ep : value["value"]) {
        MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mEpList[(EndpointId)ep.asUInt()] =
            make_shared<MatterEndpoint>(ep.asUInt(), g_DestinationNodeId);

        OC_BRG_LOG("Node (Id: 0x%lx, Product Name: \"%s\")'s endpoint (%d) is created",
            g_DestinationNodeId,
            MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mProductName.c_str(),
            ep.asUInt());
      }
    }
  } else {
    /* ----- 3. Read Descriptor cluster of all EP other than Root node EP to get Device Types & Server Cluster list ----- */
    /*
     * EP id != 0
     * - normal device type other than "root node device type"
     */
    if (value["attributeId"].asUInt() == 0) {
      /* DeviceTypeList */
      for (auto device_type : value["value"]) {
        MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mEpList[path.mEndpointId]->mDeviceTypes.insert(device_type["0"].asUInt());

        OC_BRG_LOG("Node (Id: 0x%lx, Product Name: \"%s\")'s endpoint (%d)'s devicetype is configured as (%d)",
            g_DestinationNodeId,
            MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mProductName.c_str(),
            path.mEndpointId,
            device_type["0"].asUInt());
      }
    } else if (value["attributeId"].asUInt() == 1) {
      /* ServerList */
      for (const auto & cluster_id : value["value"]) {
        MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mEpList[path.mEndpointId]->mClusterList[cluster_id.asUInt()] =
            make_shared<MatterCluster>(cluster_id.asUInt(), path.mEndpointId, g_DestinationNodeId);

        OC_BRG_LOG("Node (Id: 0x%lx, Product Name: \"%s\")'s endpoint (%d)'s cluster (%d) is added",
            g_DestinationNodeId,
            MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mProductName.c_str(),
            path.mEndpointId,
            cluster_id.asUInt());
      }
    }
  }

  return;
}


void
MatterTaskHandler::OnRetrieveCommandComplete(const chip::app::ConcreteDataAttributePath & path, const chip::TLV::TLVReader * data, const chip::app::StatusIB & status)
{
  /* --------------------------------------------------------------------------
   * 2.1 create new Node cache item
   * -------------------------------------------------------------------------*/

  CHIP_ERROR error = status.ToChipError();
  if (error != CHIP_NO_ERROR || data == nullptr) {
    OC_BRG_ERR("Something is wrong.. reading attribute %d failed!", path.mAttributeId);
    if (!--g_NumOfExpectedAttrData) {
      NOTIFY_TASK_IS_COMPLETED();
    }
    return;
  }

  Json::Value value;
  value["clusterId"]   = path.mClusterId;
  value["endpointId"]  = path.mEndpointId;
  value["attributeId"] = path.mAttributeId;

  chip::TLV::TLVReader reader;
  reader.Init(*data);
  chip::TlvToJson(reader, value);

  auto valueStr = chip::JsonToString(value);
  OC_BRG_LOG("json str: %s", valueStr.c_str());

  switch (g_OngoingCommand) {
  case MatterTaskHandler::OnGoingCommand::ONGOING_COMMAND_PAIRING:
    /* 1. ----- Read BasicInformation cluster to create Node Cache entry for target Node ----- */
    if (path.mClusterId == (ClusterId)MatterCluster::MatterClusterId::MATTER_CLUSTER_ID_BASICINFORMATION) {
      _CreateMatterNode(path, value);
    } else if (path.mClusterId == (ClusterId)MatterCluster::MatterClusterId::MATTER_CLUSTER_ID_DESCRIPTOR) {
      _CreateMatterEP(path, value);
    }
    break;

  case MatterTaskHandler::OnGoingCommand::ONGOING_COMMAND_RETRIEVE: {
    /* ----- read any cluster attribute and store it ----- */
    /* 0. find target node */
    if (MatterTranslator::mMatterNodesByNodeid.find(g_DestinationNodeId) == MatterTranslator::mMatterNodesByNodeid.end()) {
      OC_BRG_LOG("no MatterNode for 0x%lx is found!", g_DestinationNodeId);
      break;
    }

    /* 1. find corresponding Attribute of Cluster of EP of the target Node... */
    auto deviceTypes = MatterTranslator::mMatterNodesByNodeid[g_DestinationNodeId]->mEpList[path.mEndpointId]->mDeviceTypes;
    auto resourceFromClusterMapper = MatterTranslator::mOcfFromMatter[deviceTypes].RFromCMapper()[path.mClusterId];

    /* 2. Do translate... */
    resourceFromClusterMapper.PFromAMapper()[path.mAttributeId]->Translate(MatterTranslator::TransactionTranslationMode::OCF_FROM_MATTER_RETRIEVE, value["value"]);

    break;
  }

  default:
    break;
  }

  if (!--g_NumOfExpectedAttrData) {
    NOTIFY_TASK_IS_COMPLETED();
  }

  return;
}



void
MatterTaskHandler::OnRetrieveCommandCompleteError(CHIP_ERROR error)
{
  if (!CHIP_ERROR::IsSuccess(error))
    ResourceFromClusterMapper::JsonRoot()[MatterTranslator::mResultStatus] = OC_STATUS_NOT_FOUND;

  NOTIFY_TASK_IS_COMPLETED();
  return;
}



void
MatterTaskHandler::OnUpdateCommandComplete(const chip::app::ConcreteDataAttributePath & path, chip::app::StatusIB status)
{
  CHIP_ERROR error = status.ToChipError();
  if (error != CHIP_NO_ERROR) {
    OC_BRG_ERR("Something is wrong.. writing attribute %d failed!", path.mAttributeId);
    NOTIFY_TASK_IS_COMPLETED();
    return;
  }

  NOTIFY_TASK_IS_COMPLETED();
  return;
}


void
MatterTaskHandler::OnUpdateCommandCompleteError(CHIP_ERROR error)
{
  if (!CHIP_ERROR::IsSuccess(error))
    ResourceFromClusterMapper::JsonRoot()[MatterTranslator::mResultStatus] = OC_STATUS_FORBIDDEN;

  NOTIFY_TASK_IS_COMPLETED();
  return;
}


void
MatterTaskHandler::OnInvokeCommandComplete(const chip::app::ConcreteCommandPath & path, const chip::TLV::TLVReader * data, const chip::app::StatusIB & status)
{
  (void)data;

  CHIP_ERROR error = status.ToChipError();
  if (error != CHIP_NO_ERROR) {
    OC_BRG_ERR("Something is wrong.. invoking command %d failed!", path.mCommandId);
    NOTIFY_TASK_IS_COMPLETED();
    return;
  }

  NOTIFY_TASK_IS_COMPLETED();
  return;
}


void
MatterTaskHandler::OnInvokeCommandCompleteError(CHIP_ERROR error)
{
  if (!CHIP_ERROR::IsSuccess(error))
      ResourceFromClusterMapper::JsonRoot()[MatterTranslator::mResultStatus] = OC_STATUS_FORBIDDEN;

  NOTIFY_TASK_IS_COMPLETED();
  return;
}


void
MatterTaskHandler::OnDiscoveredDevice(const chip::Dnssd::DiscoveredNodeData &nodeData)
{
  printf("=> Discovered node:\n");

  if (!nodeData.resolutionData.IsHost("")) {
    printf("    |_ Hostname: %s\n", nodeData.resolutionData.hostName);
  }
#if CHIP_DETAIL_LOGGING
  for (unsigned j = 0; j < nodeData.resolutionData.numIPs; j++) {
    char buf[Inet::IPAddress::kMaxStringLength];
    char *ipAddressOut = nodeData.resolutionData.ipAddress[j].ToString(buf);
    printf("    |_ IP Address #%d: %s\n", j + 1, ipAddressOut);
  }
#endif // CHIP_DETAIL_LOGGING
  if (nodeData.resolutionData.port > 0) {
    printf("    |_ Port: %u\n", nodeData.resolutionData.port);
  }
  if (nodeData.resolutionData.mrpRetryIntervalIdle.HasValue()) {
    printf("    |_ Mrp Interval idle: %" PRIu32 " ms\n",
        nodeData.resolutionData.mrpRetryIntervalIdle.Value().count());
  } else {
    printf("    |_ Mrp Interval idle: not present\n");
  }
  if (nodeData.resolutionData.mrpRetryIntervalActive.HasValue()) {
    printf("    |_ Mrp Interval active: %" PRIu32 " ms\n",
        nodeData.resolutionData.mrpRetryIntervalActive.Value().count());
  } else {
    printf("    |_ Mrp Interval active: not present\n");
  }
  printf("    |_ TCP Supported: %d\n", nodeData.resolutionData.supportsTcp);

  if (nodeData.commissionData.rotatingIdLen > 0) {
    char rotatingIdString[chip::Dnssd::kMaxRotatingIdLen * 2 + 1] = "";
    Encoding::BytesToUppercaseHexString(nodeData.commissionData.rotatingId, nodeData.commissionData.rotatingIdLen,
        rotatingIdString, sizeof(rotatingIdString));
    printf("    |_ Rotating ID: %s\n", rotatingIdString);
  }
  if (string{nodeData.commissionData.deviceName}.size() != 0) {
    printf("    |_ Device Name: %s\n", nodeData.commissionData.deviceName);
  }
  if (nodeData.commissionData.vendorId > 0) {
    printf("    |_ Vendor ID: %u\n", nodeData.commissionData.vendorId);
  }
  if (nodeData.commissionData.productId > 0) {
    printf("    |_ Product ID: %u\n", nodeData.commissionData.productId);
  }
  if (nodeData.commissionData.deviceType > 0) {
    printf("    |_ Device Type: %" PRIu32 "\n", nodeData.commissionData.deviceType);
  }
  if (nodeData.commissionData.longDiscriminator > 0) {
    printf("    |_ Long Discriminator: %u\n", nodeData.commissionData.longDiscriminator);
  }
  if (string{nodeData.commissionData.pairingInstruction}.size() != 0) {
    printf("    |_ Pairing Instruction: %s\n", nodeData.commissionData.pairingInstruction);
  }
  if (nodeData.commissionData.pairingHint > 0) {
    printf("    |_ Pairing Hint: %u\n", nodeData.commissionData.pairingHint);
  }
  if (!nodeData.commissionData.IsInstanceName("")) {
    printf("    |_ Instance Name: %s\n", nodeData.commissionData.instanceName);
  }
  printf("    |_ Commissioning Mode: %u\n", nodeData.commissionData.commissioningMode);
}


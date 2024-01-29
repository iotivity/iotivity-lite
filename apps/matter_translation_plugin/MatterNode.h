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

using namespace ::chip;

class MatterEndpoint;
class MatterCluster;


/**
 * @brief class which maintains information of target Matter Server Node
 */
class MatterNode {
public:
  chip::NodeId mNodeId;                 ///< NodeID

  std::string mVendorName;        ///< VendorName (BasicInformation (0x28), attr id: 0x01)
  uint16_t mVendorId;             ///< VendorID (BasicInformation (0x28), attr id: 0x02)
  std::string mProductName;       ///< ProductName (BasicInformation (0x28), attr id: 0x03)
  uint16_t mProductId;            ///< ProductID (BasicInformation (0x28), attr id: 0x04)
  std::string mNodeLabel;         ///< NodeLabel (BasicInformation (0x28), attr id: 0x05)
  std::string mHwVerStr;          ///< HardwareVersionString (BasicInformation (0x28), attr id: 0x08)
  std::string mSwVerStr;          ///< SoftwareVersionString (BasicInformation (0x28), attr id: 0x0a)

  std::map<chip::EndpointId, std::shared_ptr<MatterEndpoint>> mEpList;   ///< Endpoint list included by this Node

  explicit MatterNode(chip::NodeId nodeId) : mNodeId(nodeId) {}

  /* copy constructor */
  MatterNode(const MatterNode &src) :
    mNodeId(src.mNodeId),
    mVendorName(src.mVendorName), mVendorId(src.mVendorId),
    mProductName(src.mProductName), mProductId(src.mProductId),
    mNodeLabel(src.mNodeLabel), mHwVerStr(src.mHwVerStr), mSwVerStr(src.mSwVerStr)
  {
    for (const auto & item : src.mEpList) {
      mEpList[item.first] = std::make_shared<MatterEndpoint>(*item.second);
    }
  }
  virtual ~MatterNode()
  {
    mEpList.clear();
  }

  /* copy assignment operator */
  MatterNode & operator=(const MatterNode &src)
  {
    if (this != &src) {
      mNodeId = src.mNodeId;
      mVendorName = src.mVendorName;
      mVendorId = src.mVendorId;
      mProductName = src.mProductName;
      mProductId = src.mProductId;
      mNodeLabel = src.mNodeLabel;
      mHwVerStr = src.mHwVerStr;
      mSwVerStr = src.mSwVerStr;

      mEpList.clear();
      for (const auto & item : src.mEpList) {
        mEpList[item.first] = std::make_shared<MatterEndpoint>(*item.second);
      }
    }

    return *this;
  }

  virtual void print();
};



/**
 * @brief class for Matter Endpoint
 */
class MatterEndpoint : public MatterNode {
public:
  enum class MattereEndpointId {
    MATTER_EP_ID_ROOTNODE = 0
  };

  chip::EndpointId mEpId;
  std::set<chip::DeviceTypeId> mDeviceTypes;
  size_t mOcfDeviceIndex = 0;                                   ///< corresponding OCF Device index
  std::map<chip::ClusterId, std::shared_ptr<MatterCluster>> mClusterList;

  MatterEndpoint(chip::EndpointId epId, chip::NodeId nodeId) : MatterNode(nodeId), mEpId(epId) {}

  /* copy constructor */
  MatterEndpoint(const MatterEndpoint & src) :
    MatterNode(src),
    mEpId(src.mEpId),
    mDeviceTypes(src.mDeviceTypes),
    mOcfDeviceIndex(src.mOcfDeviceIndex)
  {
    for (const auto & item : src.mClusterList) {
      mClusterList[item.first] = std::make_shared<MatterCluster>(*item.second);
    }
  }

  ~MatterEndpoint() override
  {
    mClusterList.clear();
  }

  /* copy assignment operator */
  MatterEndpoint & operator=(const MatterEndpoint &src)
  {
    if (this != &src) {
      MatterNode::operator=(src);
      mEpId = src.mEpId;
      mDeviceTypes = src.mDeviceTypes;
      mOcfDeviceIndex = src.mOcfDeviceIndex;

      mClusterList.clear();
      for (const auto & item : src.mClusterList) {
        mClusterList[item.first] = std::make_shared<MatterCluster>(*item.second);
      }
    }

    return *this;
  }

  void print() override;
};


/**
 * @brief class for Matter Cluster
 */
class MatterCluster : public MatterEndpoint {
public:
  enum class MatterClusterId {
    MATTER_CLUSTER_ID_BASICINFORMATION = 0X28,
    MATTER_CLUSTER_ID_DESCRIPTOR = 0X1d
  };

  chip::ClusterId mClusterId;
  std::set<std::shared_ptr<chip::AttributeId>> mAttributeList;

  MatterCluster(chip::ClusterId clusterId, chip::EndpointId epId, chip::NodeId nodeId) : MatterEndpoint(epId, nodeId), mClusterId(clusterId) {}

  /* copy constructor */
  MatterCluster(const MatterCluster &src) :
    MatterEndpoint(src),
    mClusterId(src.mClusterId)
  {
    for (const auto & item : src.mAttributeList) {
      mAttributeList.insert(std::make_shared<chip::AttributeId>(*item));
    }
  }

  ~MatterCluster() final
  {
    mAttributeList.clear();
  }

  /* copy assignment operator */
  MatterCluster & operator=(const MatterCluster & src)
  {
    if (this != &src) {
      MatterEndpoint::operator=(src);
      mClusterId = src.mClusterId;

      mAttributeList.clear();
      for (const auto & item : src.mAttributeList) {
        mAttributeList.insert(std::make_shared<chip::AttributeId>(*item));
      }
    }

    return *this;
  }

  void print() final;
};


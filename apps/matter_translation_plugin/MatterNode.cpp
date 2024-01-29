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


#include "MatterNode.h"


void MatterNode::print()
{
  printf("=> [ NodeId : 0x%lx ]\n", mNodeId);
  printf("=>  |_ VendorName : \"%s\"\n", mVendorName.c_str());
  printf("=>  |_ VendorId : %d\n", mVendorId);
  printf("=>  |_ ProductName : \"%s\"\n", mProductName.c_str());
  printf("=>  |_ ProductId : %d\n", mProductId);
  printf("=>  |_ NodeLabel : \"%s\"\n", mNodeLabel.c_str());
  printf("=>  |_ HardwareVersionString : \"%s\"\n", mHwVerStr.c_str());
  printf("=>  |_ SoftwareVersionString : \"%s\"\n", mSwVerStr.c_str());
  for (const auto & ep : mEpList) {
    ep.second->print();
  }
  return;
}

void MatterEndpoint::print()
{
  printf("=>  |_ EndpointId : %d\n", mEpId);

  printf("=>    |_ Device Type : ");
  for (const auto & device_type : mDeviceTypes) {
    printf("0x%x ", device_type);
  }
  printf("\n");

  for (const auto & cluster : mClusterList) {
    cluster.second->print();
  }
  return;
}


void MatterCluster::print()
{
  printf("=>    |_ ClusterId : 0x%x\n", mClusterId);

  for (const auto & attr : mAttributeList) {
    printf("=>      |_ AttributeId : %d\n", *attr);
  }
  return;
}


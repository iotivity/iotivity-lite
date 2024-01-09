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

#include "commands/common/CHIPCommand.h"

/**
 * @class MatterTaskHandler
 *
 * @brief This class includes callbacks which handles invocation results of Matter commands
 */
class MatterTaskHandler {
public:
  /**
   * @brief this indicates which Matter command is on going..
   */
  enum class OnGoingCommand {
    ONGOING_COMMAND_NONE,    ///< ONGOING_COMMAND_NONE
    ONGOING_COMMAND_PAIRING, ///< ONGOING_COMMAND_PAIRING : Pairing command is in process
    ONGOING_COMMAND_RETRIEVE,///< ONGOING_COMMAND_RETRIEVE : Read command is in process
    ONGOING_COMMAND_UPDATE   ///< ONGOING_COMMAND_UPDATE : Write command is in process
  };

  /**
   * @brief Callback on pairing command completion
   *
   * @param nodeId NodeId of target node
   */
  static void OnPairingCommandComplete(CHIPCommand::NodeId nodeId);

  /**
   * @brief Callback on read command completion
   *
   * @param path Full path of target attribute
   * @param data Attribute data encoded in TLV format
   * @param status Run result
   */
  static void OnRetrieveCommandComplete(const chip::app::ConcreteDataAttributePath & path, const chip::TLV::TLVReader * data, const chip::app::StatusIB & status);

  /**
   * @brief Callback on read command error
   *
   * @param error Error info
   */
  static void OnRetrieveCommandCompleteError(CHIP_ERROR error);

  /**
   * @brief Callback on write command completion
   *
   * @param path Full path of target attribute
   * @param status Run result
   */
  static void OnUpdateCommandComplete(const chip::app::ConcreteDataAttributePath & path, chip::app::StatusIB status);

  /**
   * @brief Callback on write command error
   *
   * @param error Error info
   */
  static void OnUpdateCommandCompleteError(CHIP_ERROR error);

  /**
   * @brief Callback on invoke command completion
   *
   * @param path Full path of target attribute
   * @param data Attribute data encoded in TLV format
   * @param status Run result
   */
  static void OnInvokeCommandComplete(const chip::app::ConcreteCommandPath & path, const chip::TLV::TLVReader * data, const chip::app::StatusIB & status);

  /**
   * @brief Callback on invoke command error
   *
   * @param error Error info
   */
  static void OnInvokeCommandCompleteError(CHIP_ERROR error);

  /**
   * @brief Callback on Discover command completion
   *
   * @param nodeData Discovered node data
   */
  static void OnDiscoveredDevice(const chip::Dnssd::DiscoveredNodeData &nodeData);
};



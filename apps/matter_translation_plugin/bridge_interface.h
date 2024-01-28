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

#include "oc_helpers.h"
#include "oc_endpoint.h"
#include "oc_rep.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#include "oc_export.h"

#include "matter_log.h"
#include "common/ecosystem_command.h"
#include "commands/common/CHIPCommand.h"

#include "MatterTranslator.h"
#include "MatterTaskHandler.h"
#include "MatterNode.h"

#include <map>

#ifdef __cplusplus
extern "C" {
#endif

/* (sub)commands of "discover" command */
#define VALUE_CMD_DISCOVER "discover"
#define VALUE_SUBCMD_DISCOVER_LIST "list"
#define VALUE_SUBCMD_DISCOVER_COMMISSIONABLES "commissionables"
#define VALUE_SUBCMD_DISCOVER_COMMISSIONERS "commissioners"

/* (sub)commands of "pairing" command */
#define VALUE_CMD_PAIRING "pairing"
#define VALUE_SUBCMD_PAIRING_ONNETWORK "onnetwork"
#define VALUE_SUBCMD_PAIRING_ONNETWORK_INSTANCE_NAME "onnetwork-instance-name"
#define VALUE_SUBCMD_PAIRING_UNPAIR "unpair"

/**
 * @brief initialize plugin
 * @param cli_commandset Ecosystem-specific commandset which should be
 *                       completed by plugin
 * @return 0: success, <0: failure
 */
OC_API int InitPlugin(ecosystem_cli_commandset_t *cli_commandset);

/**
 * @brief shutdown plugin
 * @param cli_commandset Ecosystem-specific commandset
 * @return 0: success, <0: failure
 */
OC_API int ShutdownPlugin(ecosystem_cli_commandset_t *cli_commandset);

/**
 * @brief thread waiting for the completion of subtask of each command handler
 */
extern pthread_mutex_t g_TaskWaiterLock;
extern pthread_cond_t g_CondTaskIsCompleted;

/**
 * @brief current destination Node ID
 */
extern NodeId g_DestinationNodeId;

/**
 * @brief keeps information of current running command
 * - to decide which action should be done in ONE COMMON retrieval response callback function..
 */
extern pthread_mutex_t g_OngoingCommandLock;
extern MatterTaskHandler::OnGoingCommand g_OngoingCommand;

/**
 * @brief "ReportCommand::OnAttributeData()" is called repeatedly for each attribute data.
 * so this value is used to decide when we wakeup "task_completion_waiter" thread..
 * (we have to wait until every attribute date is received..)
 */
extern int g_NumOfExpectedAttrData;


#define NOTIFY_TASK_IS_COMPLETED() \
    do { \
      pthread_mutex_lock(&g_TaskWaiterLock); \
      pthread_cond_signal(&g_CondTaskIsCompleted); \
      OC_BRG_LOG("==========> \"%s\" is done! so notify \"bridge_interface\" to resume next task <==========", __func__); \
      pthread_mutex_unlock(&g_TaskWaiterLock); \
    } while (0)

#define SET_ONGOING_COMMAND(command) \
    do { \
      pthread_mutex_lock(&g_OngoingCommandLock); \
      g_OngoingCommand = (command); \
    } while(0)

#define UNSET_ONGOING_COMMAND() \
    do { \
      g_OngoingCommand = MatterTaskHandler::OnGoingCommand::ONGOING_COMMAND_NONE; \
      pthread_mutex_unlock(&g_OngoingCommandLock); \
    } while(0)

#define RUN_MATTER_COMMAND(commandStr) \
    do { \
      int tokenc = 0; \
      char **tokenv; \
      tokenv = MatterTranslator::ConvertStrToTokenArray((commandStr), &tokenc); \
      RunMatterCommand(tokenc, tokenv); \
      MatterTranslator::FreeTokenArray(tokenv, tokenc); \
    } while(0)

#ifdef __cplusplus
}
#endif

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

#ifndef BRIDGE_MANAGER_H_
#define BRIDGE_MANAGER_H_


#include "oc_export.h"
#include "oc_helpers.h"
#include "oc_uuid.h"
#include "oc_core_res.h"
#include "oc_vod_map.h"
#include "oc_endpoint.h"
#include "oc_ri.h"
#include "oc_bridge.h"
#include "port/oc_connectivity.h"
#include "util/oc_memb.h"
#include "util/oc_list.h"

#include "common/ecosystem_command.h"

#include <string.h>
#include <pthread.h>

/*---------------------------------------------------------------------------*/
/*
 * Log macro for bridge manager
 */
/*---------------------------------------------------------------------------*/
#ifdef OC_BRG_DEBUG
#define OC_BRG_LOG(...) \
  do { \
    printf("=> %s:%d <%s()>: ", __FILE__, __LINE__, __func__); \
    printf(__VA_ARGS__); \
    printf("\n"); \
  } while(0)
#else
#define OC_BRG_LOG(...)
#endif

#define OC_BRG_ERR(...) \
  do { \
    printf("=> %s:%d <%s()>: ", __FILE__, __LINE__, __func__); \
    printf(__VA_ARGS__); \
    printf("\n"); \
  } while(0)



/*-----------------------------------------------------------------------------*/
/*
 * bridge manager interface APIs
 */
/*-----------------------------------------------------------------------------*/
/**
 * @brief initialize bridge_manager
 * @return 0: success, <0: failure
 */
OC_API int init_bridge_manager(void);

/**
 * @brief shutdown bridge_manager
 * @return none
 */
OC_API void shutdown_bridge_manager(void);


/*---------------------------------------------------------------------------*/
/*
 *  vod command
 */
/*---------------------------------------------------------------------------*/
/**
 * @brief "vod" command handler
 *
 * @param parsed_command_json_str Serialized json string stream including "vod" command info typed by a user
 * @return NULL: error, non NULL: Serialized json string stream including list of VODs
 */
OC_API char *vod(char *parsed_command_json_str);


/*---------------------------------------------------------------------------*/
/*
 *  cd command
 */
/*---------------------------------------------------------------------------*/
/**
 * @brief "cd" command handler (used to enter specific ecosystem CLI mode)
 *
 * @param module_name Name of a plugin module (e.g. "matter")
 * @return 0: success, <0: failure
 */
OC_API int cd(char *module_name);


/*---------------------------------------------------------------------------*/
/*
 *  module command
 */
/*---------------------------------------------------------------------------*/
/**
 * @brief "module" command handler
 *
 * @param parsed_command_json_str Serialized json string stream including "module" command info typed by a user
 * @return 0: success, <0: failure
 */
OC_API int module(char *parsed_command_json_str);


/*---------------------------------------------------------------------------*/
/*
 *  retrieve command
 */
/*---------------------------------------------------------------------------*/
/**
 * @brief "retrieve" command handler
 *
 * @param parsed_command_json_str Serialized json string stream including "retrieve" command info typed by a user
 * @return 0: success, <0: failure
 */
OC_API int retrieve(char *parsed_command_json_str);


/*---------------------------------------------------------------------------*/
/*
 *  update command
 */
/*---------------------------------------------------------------------------*/
/**
 * @brief "update" command handler
 *
 * @param parsed_command_json_str Serialized json string stream including "update" command info typed by a user
 * @return 0: success, <0: failure
 */
OC_API int update(char *parsed_command_json_str);


/*---------------------------------------------------------------------------*/
/*
 *  Ecosystem specific command
 */
/*---------------------------------------------------------------------------*/
/**
 * @brief Run ecosystem specific command
 *
 * @param parsed_command_json_str Serialized json string stream including ecosystem-specific command info typed by a user
 * @return 0: success, <0: failure
 */
OC_API int run_ecosystem_command(char *parsed_command_json_str);


/*
 * for testing purpose
 */
#ifdef OC_BRG_DEBUG
OC_API void add_vods_test(void);
#endif

#endif /* BRIDGE_MANAGER_H_ */

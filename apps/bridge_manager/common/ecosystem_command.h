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

#ifndef COMMON_ECOSYSTEM_COMMAND_H_
#define COMMON_ECOSYSTEM_COMMAND_H_


#include "oc_rep.h"
#include "oc_helpers.h"
#include "oc_ri.h"
#include "util/oc_list.h"


/*---------------------------------------------------------------------------*/
/*
 *  function pointer types for ecosystem-specific callback APIs that each
 *  translation plugin should implement.
 */
/*---------------------------------------------------------------------------*/

typedef struct ecosystem_cli_commandset ecosystem_cli_commandset_t;


/**
 * @brief callback for other ecosystem specific commands
 *
 * @param parsed_command_json_str Serialized json string stream including "vod" command info typed by a user
 * @return 0: success, <0: failure
 */
typedef int (*cb_ecosystem_command_t)(const char *parsed_command_json_str);

/**
 * @brief callback to initiate ecosystem translation plugin
 *
 * @param cli_commandset Ecosystem-specific commandset which should be completed by plugin
 * @return 0: success, <0: failure
 */
typedef int (*cb_init_plugin_t)(ecosystem_cli_commandset_t *cli_commandset);

/**
 * @brief callback to shutdown ecosystem translation plugin
 *
 * @param cli_commandset Ecosystem-specific commandset which should be cleaned by plugin
 * @return 0: success, <0: failure
 */
typedef int (*cb_shutdown_plugin_t)(ecosystem_cli_commandset_t *cli_commandset);



/*---------------------------------------------------------------------------*/
/*
 * structs for each ecosystem-specific commandset
 */
/*---------------------------------------------------------------------------*/

/**
 * @brief ecosystem specific command
 */
typedef struct cli_command {
  struct cli_command *next;
  oc_string_t cmd_str;          ///< ecosystem specific command string
  cb_ecosystem_command_t func;  ///< callback to handle this command
} cli_command_t;

/**
 * @brief ecosystem commandset
 */
typedef struct ecosystem_cli_commandset {
  struct ecosystem_cli_commandset *next;

  oc_string_t econame;                ///< ecosystem name providing these command set (set by plugin)
  cb_init_plugin_t init;              ///< callback to init this ecosystem translation plugin (set by bridge_manager)
  cb_shutdown_plugin_t shutdown;      ///< callback to shutdown this ecosystem translation plugin (set by bridge_manage)
  cb_ecosystem_command_t retrieve;    ///< callback to retrieve data from ecosystem server (set by plugin)
  cb_ecosystem_command_t update;      ///< callback to update data in ecosystem server (set by plugin)
  OC_LIST_STRUCT(eco_commands);       ///< callbacks for ecosystem-specific commands (e.g. discover, pairing...) (set by plugin)
  void *dl_plugin_handle;             ///< plugin handle (set by bridge_manage)
} ecosystem_cli_commandset_t;


/**
 * @brief available subcommand list
 */
/* subcommands of "module" command */
#define VALUE_SUBCMD_MODULE_LIST "list"
#define VALUE_SUBCMD_MODULE_LOAD "load"
#define VALUE_SUBCMD_MODULE_UNLOAD "unload"

/* subcommands of "vod" command */
#define VALUE_SUBCMD_VOD_LIST "list"
#define VALUE_SUBCMD_VOD_ADD "add"
#define VALUE_SUBCMD_VOD_DELETE "delete"


/**
 * json keys for parsed commands from bridge_cli
 */
#define KEY_CMD "cmd"
#define KEY_SUBCMD "subcmd"
#define KEY_OPTIONS "options"
#define KEY_ECONAME "econame"
#define KEY_VALUE "value"
#define KEY_CMDSTR "cmd_str"


/*
 * if c++ is used, below macros are not required
 */
#define CLI_JSON_LOADS(json_str, error_return_value) \
    json_error_t json_error; \
    json_t *json_root; \
    do { \
      if (!(json_root = json_loads((json_str), 0, &json_error))) { \
        OC_BRG_ERR("%s", json_error.text); \
        return (error_return_value); \
      } \
    } while (0)

#define CLI_JSON_CLOSE() \
    json_decref(json_root)

#define CLI_JSON_STRING_VALUE(object, key) \
    json_string_value(json_object_get((object), (key)))

#define CLI_JSON_INT_VALUE(object, key) \
    json_integer_value(json_object_get((object), (key)))



#endif /* COMMON_ECOSYSTEM_COMMAND_H_ */

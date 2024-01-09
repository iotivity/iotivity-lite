#==============================================================================
#
# Copyright 2023 ETRI All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"),
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
#
# Created on: Aug 20, 2023,
#        Author: Joo-Chul Kevin Lee (rune@etri.re.kr)
#
#
#==============================================================================

import os
import importlib
import sys

from json import loads, dumps

from logging import basicConfig, getLogger, DEBUG, ERROR
from ctypes import CDLL
from readline import get_begidx, get_line_buffer, get_endidx, get_completer_delims, set_completer_delims, set_completer, parse_and_bind
from pandas import DataFrame
import pandas

from debug import cli_log, CliRunError
from common.command import Option, Command
from bridge_manager import ffi, lib
from vod_manager import VodManager as vm
from iotivity import Iotivity as iot


# =============================================================================
# global variables
# =============================================================================

class CliManager:
   """CliManager
   CLI command manager

   Attributes:
      command_tokens (list): list of current tokens (tokens before the token which is being completed...)
      current_token (str): the token which is being completed...
      current_parsed_command (dict): current parsed command
      current_econame (string): current activated ecosystem bridge module name
      all_econames (list): all loaded ecosystem bridge module list
      current_prompt (string): current CLI prompt string
      eco_command_list (dict): eco-specific commands list
      command_list (dict): common commands list
      logger (logger): logger object
      token_candidate_list (list): candidate token list for the token which is being input
      vodinfos (VodManager): maintains VOD information list
   """

   def __init__(self, print_log: bool = False) -> None:
      """__init__ register common commands

      Args:
         print_log (bool) : switch to print log message
      """
      self.command_tokens = []
      self.current_token = ''
      self.current_parsed_command = { 'cmd': None, 'subcmd': None, 'options' : [], 'econame' : None }
      self.current_econame = ''
      self.all_econames = set()
      # ansi prompt makes trouble in gnome-terminal.., so commented out now
      # self.current_prompt = '\033[92mbridge> \033[m'
      self.current_prompt = '\nbridge > '
      self.eco_command_list = dict()
      self.token_candidate_list = []
      self.vodinfos = None

      basicConfig(format='=> [%(levelname)s]:%(name)s:%(funcName)s():%(lineno)d - %(message)s')
      self.logger = getLogger('cli_manager')
      if print_log:
         self.logger.setLevel(DEBUG)
      else:
         self.logger.setLevel(ERROR)

      # =============================================================================
      # CLI subcommands, options
      # =============================================================================

      # bridge> module ...
      _module_subcmds = {
         'list' : Command('list'),
         'load' : Command('load', re=r'(\s*[\w\-]+\s*)*\s*[\w\-]+\s*', parse=self._cb_parse_module,
                        generator=self._cb_generator_module),
         'unload' : Command('unload', re=r'(\s*[\w\-]+\s*)*\s*[\w\-]+\s*', parse=self._cb_parse_module,
                           generator=self._cb_generator_module)
         }

      # bridge> vod ...
      _vod_subcmds = {
         'list' : Command('list', re=r'(\s*[\d]+\s*)*', parse=self._cb_parse_vod, generator=self._cb_generator_vod),
         'add' : Command('add', re=r'(\s*[\w\-:@]+\s*)*\s*[\w\-:@]+\s*', parse=self._cb_parse_vod,
                        generator=self._cb_generator_vod),
         'delete' : Command('delete', re=r'(\s*[\w\-:@]+\s*)*\s*[\w\-:@]+\s*', parse=self._cb_parse_vod,
                        generator=self._cb_generator_vod)
         }

      # bridge> retrieve {-name|-id} ...
      _retrieve_options = {
         '-name' : Option('-name', re=r'\s*([\w\-:@]+/)+[\w\-]+\s*', parse=self._cb_parse_retrieve,
                        generator=self._cb_generator_retrieve),
         '-id' : Option('-id', re=r'\s*([\w\-]+/)+[\w\-]+\s*', parse=self._cb_parse_retrieve,
                        generator=self._cb_generator_retrieve)
         }



      # bridge> update {-name|-id} ...
      _update_options = {
         '-name' : Option('-name', re=r'\s*([\w\-:@]+/)+[\w\-]+\s*',
                        parse=self._cb_parse_update,
                        generator=self._cb_generator_update),
         '-id' : Option('-id', re=r'\s*([\w\-]+/)+[\w\-]+\s*',
                        parse=self._cb_parse_update,
                        generator=self._cb_generator_update),
         '-value' : Option('-value', re='json',
                        parse=self._cb_parse_update,
                        generator=self._cb_generator_update)
         }

      # common commands list
      self.command_list = {
         'cd' : Command('cd', re=r'\s*\.\.|[\w\-]+\s*',
                        action=self._cb_action_cd, parse=self._cb_parse_cd,
                        generator=self._cb_generator_cd, help='cd { .. | <econame> }\n    load econame module if it is not loaded, and provides ecosystem specific commands'),
         'module' : Command('module', sub_cmds=_module_subcmds,
                           action=self._cb_action_module,
                           generator=self._cb_generator_module, help='module { list | load | unload } <econame1>, <econame2>, ...\n    list, load, unload module(s)'),
         'vod' : Command('vod', sub_cmds=_vod_subcmds,
                           action=self._cb_action_vod,
                           generator=self._cb_generator_vod, help='vod { list [ <vod-number1>, <vod-number2>, ... ] | delete <vod-name1>, <vod-name2>, ... | add <vod-name1>, <vod-name2>, ... }\n    list, delete, add VOD'),
         'retrieve' : Command('retrieve', options=_retrieve_options,
                           action=self._cb_action_retrieve,
                           generator=self._cb_generator_retrieve, help='retrieve { -name <vod-name>/<resource-path> | -id <vod-id>/<resource-path> }\n    retrieve resource values'),
         'update' : Command('update', options=_update_options,
                           action=self._cb_action_update,
                           generator=self._cb_generator_update, help='update { -name <vod-name>/<resource-path> | -id <vod-id>/<resource-path> } -value <json formatted string for property:value>\n    update resource values\n    e.g.) -value { "value": true, "string": "100", "array": [ 10, 20 ], "obj": { "value": true } }'),
         'help' : Command('help', re=r'(\s*[\w]+\s*)*\s*[\w]+\s*',
                           action=self._cb_action_help, parse=self._cb_parse_help,
                           generator=self._cb_generator_help, help='help [ <command1>, <command2>, ... ]')
         }


   # =============================================================================
   # CLI callback functions
   # =============================================================================

   def _parsed_command_dumps(self, parsed_command: dict) -> bytes:
      """_convert_parsed_command_to_json(): dumps current_parsed_command dict into json str

      Args:
          parsed_command (dict): current_parsed_command

      Returns:
          str: json byte str
      """
      return iot.str_to_string(dumps({
                     'cmd': {
                        'cmd_str': parsed_command['cmd'].cmd_str if parsed_command['cmd'] else None,
                        'value' : parsed_command['cmd'].value if parsed_command['cmd'] else None
                     },
                     'subcmd': {
                        'cmd_str': parsed_command['subcmd'].cmd_str if parsed_command['subcmd'] else None,
                        'value': parsed_command['subcmd'].value if parsed_command['subcmd'] else None
                     },
                     'options':
                        list(map(lambda x: { 'cmd_str': x.cmd_str if x else None, 'value' : x.value if x else None }, parsed_command['options'])),
                     'econame': parsed_command['econame']
                  }))

   # --------------------------------------------------------------------------
   # bridge> cd ...
   # cd <econame>
   # cd ..
   # --------------------------------------------------------------------------
   def _cb_action_cd(self, cli_mgr: object) -> bool:
      """_cb_action_cd(): callback for running "cd" command

      Args:
          cli_mgr (object): CliManager instance

      Returns:
          bool: running result
      """

      if cli_mgr.current_parsed_command['cmd'].value not in (['..'] + list(cli_mgr.eco_command_list)):
         return False

      if cli_mgr.current_parsed_command['cmd'].value == '..':
         if cli_mgr.current_econame:
            # ecosystem mode => common mode
            # ANSI-enabled prompt: cli_mgr.current_prompt = cli_mgr.current_prompt.replace('/\033[91m'+cli_mgr.current_econame+'\033[m\033[92m', '')
            cli_mgr.current_prompt = cli_mgr.current_prompt.replace('/ '+cli_mgr.current_econame+' ', '')
            cli_mgr.current_econame = ''
      elif not cli_mgr.current_econame:
         # common mode => ecosystem mode
         # ANSI-enabled prompt : cli_mgr.current_prompt = cli_mgr.current_prompt.replace('> ', '/\033[91m'+cli_mgr.current_parsed_command['cmd'].value+'\033[m\033[92m> ')
         cli_mgr.current_prompt = cli_mgr.current_prompt.replace('> ', '/ '+cli_mgr.current_parsed_command['cmd'].value+' > ')
         cli_mgr.current_econame = cli_mgr.current_parsed_command['cmd'].value
         # invoke callback of bridge_manager
         if lib.cd(iot.str_to_string(cli_mgr.current_parsed_command['cmd'].value)) < 0:
            self.logger.error(f'invoking bridge_manager.cd({cli_mgr.current_parsed_command["cmd"].value}) failed!')
            return False
         else:
            cli_mgr.all_econames |= set([cli_mgr.current_parsed_command['cmd'].value])
      else:
         # ecosystem-#1 mode => ecosystem-#2 mode
         # ANSI-enabled prompt : cli_mgr.current_prompt = cli_mgr.current_prompt.replace('/\033[31m'+cli_mgr.current_econame+'\033[m', '/\033[31m'+cli_mgr.current_parsed_command['cmd'].value+'\033[m')
         cli_mgr.current_prompt = cli_mgr.current_prompt.replace(cli_mgr.current_econame, cli_mgr.current_parsed_command['cmd'].value)
         cli_mgr.current_econame = cli_mgr.current_parsed_command['cmd'].value
         # invoke callback of bridge_manager
         if lib.cd(iot.str_to_string(cli_mgr.current_parsed_command['cmd'].value)) < 0:
            self.logger.error(f'invoking bridge_manager.cd({cli_mgr.current_parsed_command["cmd"].value}) failed!')
            return False
         else:
            cli_mgr.all_econames |= set([cli_mgr.current_parsed_command['cmd'].value])

      return True

   def _cb_parse_cd(self, arg: Option, value: list[str], cli_mgr: object = None) -> int:
      """_cb_parse_cd() : parse `value`, save it in `arg.value` if it is valid, and return result

      Args:
         token (Option): current target argument (`Command` or `Option`) that takes `value` as its parameter value
         value (list): all remaining string after this [Sub]Command which calls this parser

      Returns:
          int: `>=0`: the number of tokens to be skpped next turn
               `< 0`: parse error!
      """

      # e.g.) cd .. | cd matter
      value_exp = " ".join(value)
      # evaluate if this value has correct format...
      result, _, _ = arg._validate_value(value_exp, True)
      if result:
         # store parameter value for firing the whole command...
         arg.value = value_exp
         return len(value)
      else:
         return -1


   def _cb_generator_cd(self, text: str, cli_mgr: object = None) -> list[str]:
      """_cb_generator_cd() : generate string list starting with "text" substring

      Args:
         text (str): substring which is being input

      Returns:
         list[str]: list of candidate string starting with "text"
      """
      self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ n for n in (list(self.eco_command_list) + [".."]) if n.startswith(text) ]}')
      return [ n for n in (list(self.eco_command_list) + ['..']) if n.startswith(text) ]


   # --------------------------------------------------------------------------
   # bridge> module ...
   # module list
   # --------------------------------------------------------------------------
   # bridge> module load ...
   # module load { <module_name>, ... }
   # --------------------------------------------------------------------------
   # bridge> module unload ...
   # module unload { <module_name>, ... }
   # --------------------------------------------------------------------------

   def _cb_action_module(self, cli_mgr: object) -> bool:
      """_cb_action_module(): callback for running "module" command

      Args:
          cli_mgr (object): CliManager instance

      Returns:
          bool: running result
      """
      if (cli_mgr.current_parsed_command['subcmd'].cmd_str == 'load' or cli_mgr.current_parsed_command['subcmd'].cmd_str == 'unload') \
         and (not cli_mgr.current_parsed_command['subcmd'].value):
         cli_mgr.logger.debug(f'required parameter values of "{cli_mgr.current_parsed_command["subcmd"].cmd_str}" are missing!')
         return False

      if lib.module(cli_mgr._parsed_command_dumps(cli_mgr.current_parsed_command)) < 0:
         return False
      else:
         if cli_mgr.current_parsed_command['subcmd'].value:
            if cli_mgr.current_parsed_command['subcmd'].cmd_str == 'load':
               cli_mgr.all_econames |= set(cli_mgr.current_parsed_command['subcmd'].value)
            elif cli_mgr.current_parsed_command['subcmd'].cmd_str == 'unload':
               cli_mgr.all_econames -= set(cli_mgr.current_parsed_command['subcmd'].value)

         return True


   def _cb_generator_module(self, text: str, cli_mgr: object = None) -> list[str]:
      """_cb_generator_module() : generate string list starting with "text" substring

      Args:
         text (str): substring which is being input

      Returns:
         list[str]: list of candidate string starting with "text"
      """

      if self.current_token.cmd_str == 'module':
         # module ...
         self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ n for n in list(self.command_list["module"].sub_cmds) if n.startswith(text) ]}')
         return [ n for n in list(self.command_list['module'].sub_cmds) if n.startswith(text) ]
      elif self.current_token.cmd_str == 'load':
         # module load ...
         self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ n for n in list(self.eco_command_list) if n.startswith(text) ]}')
         return [ n for n in list(self.eco_command_list) if n.startswith(text) ]
      elif self.current_token.cmd_str == 'unload':
         # module unload ...
         self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ n for n in self.all_econames if n.startswith(text) ]}')
         return [ n for n in self.all_econames if n.startswith(text) ]
      else:
         return []


   def _cb_parse_module(self, arg: Option, value: list[str], cli_mgr: object = None) -> int:
      """_cb_parse_module() : parse `value`, save it in arg.value if it is valid, and return result

      Args:
         token (Option): current target argument (`Command` or `Option`) that takes `value` as its parameter value
         value (list): all remaining string after this [Sub]Command which calls this parser

      Returns:
          int: `>=0`: the number of tokens to be skpped next turn
               `< 0`: parse error!
      """

      value_exp = " ".join(value)
      # evaluate if this value has correct format...
      result, _, _ = arg._validate_value(value_exp, True)
      if result:
         # store parameter value for firing the whole command...
         arg.value = value
         return len(value)
      else:
         return -1


   # --------------------------------------------------------------------------
   # bridge> vod ...
   # vod list
   # --------------------------------------------------------------------------
   # bridge> vod add ...
   # vod add { <vod-id>, ... }
   # --------------------------------------------------------------------------
   # bridge> vod delete ...
   # vod delete { <vod-id>, ... }
   # --------------------------------------------------------------------------

   def _action_vod_list(self, cli_mgr: object) -> bool:
      """_action_vod_list() : handle "vod list" command

      Args:
          cli_mgr (cli_manager): CLI manager instance

      Returns:
          bool: operation result
      """
      cli_mgr.vodinfos = vm(lib.vod(cli_mgr._parsed_command_dumps(cli_mgr.current_parsed_command)))
      if cli_mgr.vodinfos:
         if cli_mgr.current_parsed_command['subcmd'].value:
            # if the user provides specific list of VOD index, show those VODs only..
            for n in cli_mgr.current_parsed_command['subcmd'].value:
               if int(n) < len(cli_mgr.vodinfos.vodinfo_table):
                  pandas.set_option('display.max_colwidth', 350)
                  print(f'{cli_mgr.vodinfos.vodinfo_table.iloc[int(n)]}')
                  pandas.set_option('display.max_colwidth', 50)
               else:
                  return False
         else:
            # if the user provides NO specific list of VOD index, show whole VODs list..
            print(f'{cli_mgr.vodinfos}')
      return True


   def _cb_action_vod(self, cli_mgr: object) -> bool:
      """_cb_action_vod(): callback for running "vod" command

      Args:
         cli_mgr (object): CliManager instance

      Returns:
         bool: running result
      """

      # [ ] TODO: update value check codes of all "action" method with following code
      # if (cli_mgr.current_parsed_command['subcmd']
      #     and cli_mgr.current_parsed_command['subcmd'].re
      #     and not cli_mgr.current_parsed_command['subcmd'].value):
      #    cli_mgr.logger.debug(f'required parameter values of "{cli_mgr.current_parsed_command["subcmd"].cmd_str}" are missing!')
      #    return False

      if (cli_mgr.current_parsed_command['subcmd'].cmd_str == 'add' or cli_mgr.current_parsed_command['subcmd'].cmd_str == 'delete') \
         and (not cli_mgr.current_parsed_command['subcmd'].value):
         cli_mgr.logger.debug(f'required parameter values of "{cli_mgr.current_parsed_command["subcmd"].cmd_str}" are missing!')
         return False

      if cli_mgr.current_parsed_command['subcmd'].cmd_str == 'list':
         # ----- vod list command -----
         cli_mgr.logger.debug(f'vod list: \n{dumps(loads(ffi.string(lib.vod(cli_mgr._parsed_command_dumps(cli_mgr.current_parsed_command)))), indent=2)}')
         if not self._action_vod_list(cli_mgr):
            return False
      elif cli_mgr.current_parsed_command['subcmd'].cmd_str == 'add' or cli_mgr.current_parsed_command['subcmd'].cmd_str == 'delete':
         # ----- vod add | delete command -----
         # gets "Device ID" for the "Device Name", and pass them to the "bridge_manager"...
         cli_mgr.current_parsed_command['subcmd'].value = list(cli_mgr.vodinfos.vodinfo_table[cli_mgr.vodinfos.vodinfo_table['device_name'].isin(cli_mgr.current_parsed_command['subcmd'].value)]['di'])
         lib.vod(cli_mgr._parsed_command_dumps(cli_mgr.current_parsed_command))
      else:
         return False

      return True


   def _cb_generator_vod(self, text: str, cli_mgr: object = None) -> list[str]:
      """_cb_generator_vod() : generate string list starting with "text" substring

      Args:
         text (str): substring which is being input

      Returns:
         list[str]: list of candidate string starting with "text"
      """

      if self.current_token.cmd_str == 'vod':
         # vod ...
         self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ n for n in list(self.command_list["vod"].sub_cmds) if n.startswith(text) ]}')
         return [ n for n in list(self.command_list["vod"].sub_cmds) if n.startswith(text) ]
      elif self.current_token.cmd_str == 'list':
         # vod list ...
         if self.vodinfos:
            self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ str(n) for n in range(len(self.vodinfos.vodinfo_table)) if str(n).startswith(text) ]}')
            return [ str(n) for n in range(len(self.vodinfos.vodinfo_table)) if str(n).startswith(text) ]
         else:
            return []
      elif self.current_token.cmd_str == 'add':
         # [ ] TODO: change search key from "device name" to "device ID" (because device name could be duplicated)
         # vod delete ...
         if self.vodinfos:
            self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ n for n in self.vodinfos.vodinfo_table[ self.vodinfos.vodinfo_table["is_online"]==False ]["device_name"] if n.startswith(text) ]}')
            return [ n for n in self.vodinfos.vodinfo_table[ self.vodinfos.vodinfo_table['is_online']==False ]['device_name'] if n.startswith(text) ]
         else:
            return []
      elif self.current_token.cmd_str == 'delete':
         # vod delete ...
         if self.vodinfos:
            self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ n for n in self.vodinfos.vodinfo_table[ self.vodinfos.vodinfo_table["is_online"]==True ]["device_name"] if n.startswith(text) ]}')
            return [ n for n in self.vodinfos.vodinfo_table[ self.vodinfos.vodinfo_table['is_online']==True ]['device_name'] if n.startswith(text) ]
         else:
            return []
      else:
         return []


   def _cb_parse_vod(self, arg: Option, value: list[str], cli_mgr: object = None) -> int:
      """_cb_parse_vod_list() : parse `value`, save it in arg.value if it is valid, and return result

      Args:
         token (Option): current target argument (`Command` or `Option`) that takes `value` as its parameter value
         value (list): all remaining string after this [Sub]Command which calls this parser

      Returns:
          int: `>=0`: the number of tokens to be skpped next turn
               `< 0`: parse error!
      """
      value_exp = " ".join(value)
      # evaluate if this value has correct format...
      result, _, _ = arg._validate_value(value_exp, True)
      if result:
         # store parameter value for firing the whole command...
         arg.value = value
         return len(value)
      else:
         return -1


   # --------------------------------------------------------------------------
   # bridge> retrieve ...
   # --------------------------------------------------------------------------
   # bridge> retrieve -name ...
   # retrieve -name <device_name>/<resource_path>
   # --------------------------------------------------------------------------
   # bridge> retrieve -id ...
   # retrieve -id <device_id>/<resource_path>
   # --------------------------------------------------------------------------
   def _convert_name_to_id(self, option_list: list[Option], vod_table: DataFrame) -> (bool, list[Option], str):
      """_convert_name_to_id() : handle "-name" or "-id" option of retrieve/update command

      Args:
         option (Option): Option instance
         vod_table (DataFrame): DataFrame including VODs information

      Returns:
         bool: operation result
         list[Option]: Option list
         str: vod econame
      """
      for option in option_list:
         if option.cmd_str == '-name':
            vod_name = option.value.split(sep='/')[0]
            if vod_table[vod_table['device_name'] == vod_name].empty:
               self.logger.error(f'{vod_name} is not found!')
               return (False, option_list, None)
            vod_id = list(vod_table[vod_table['device_name'] == vod_name]['di'])[0]
            option.value = option.value.replace(vod_name, vod_id)
            vod_econame = list(vod_table[vod_table['device_name'] == vod_name]['econame'])[0]
            self.logger.debug(f'{vod_name}\'s di: {vod_id}, econame: "{vod_econame}"')
         elif option.cmd_str == '-id':
            vod_id = option.value.split(sep='/')[0]
            if vod_table[vod_table['di'] == vod_id].empty:
               self.logger.error(f'{vod_id} is not found!')
               return (False, option_list, None)
            vod_econame = list(vod_table[vod_table['di'] == vod_id]['econame'])[0]
            self.logger.debug(f'{vod_id}\'s econame: "{vod_econame}"')
         elif option.cmd_str == '-value':
            self.logger.debug(f'update value: "{option.value}"')

      return (True, option_list, vod_econame)


   def _cb_action_retrieve(self, cli_mgr: object) -> bool:
      """_cb_action_retrieve(): callback for running "retrieve" command

      Args:
         cli_mgr (object): CliManager instance

      Returns:
         bool: running result
      """
      if not cli_mgr.vodinfos:
         self.logger.debug('vodinfo table has not been initialized, do "vod list" first!')
         return False

      vod_table = cli_mgr.vodinfos.vodinfo_table
      option_list = cli_mgr.current_parsed_command['options']

      # check existence of value for each option
      for option in option_list:
         if option.re and not option.value:
            cli_mgr.logger.debug(f'required parameter values of "{option.cmd_str}" are missing!')
            return False

      if len(option_list) != 1:
         cli_mgr.logger.error('retrieve command requires 1 option: -name/-id')
         return False

      # convert VOD name into VOD ID
      result, cli_mgr.current_parsed_command['options'], vod_econame = self._convert_name_to_id(option_list, vod_table)
      if not result:
         return False

      # specify which ecosystem this VOD belongs to..
      cli_mgr.current_parsed_command['econame'] = vod_econame

      if lib.retrieve(cli_mgr._parsed_command_dumps(cli_mgr.current_parsed_command)) < 0:
         return False

      return True


   def _cb_generator_retrieve(self, text: str, cli_mgr: object = None) -> list[str]:
      """_cb_generator_retrieve() : generate string list starting with "text" substring

      Args:
         text (str): substring which is being input

      Returns:
         list[str]: list of candidate string starting with "text"
      """
      if self.current_token.cmd_str == 'retrieve':
         # retrieve ...
         self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ n for n in list(self.command_list["retrieve"].options) if n.startswith(text) ]}')
         return [ n for n in list(self.command_list["retrieve"].options) if n.startswith(text) ]
      elif self.current_token.cmd_str == '-name':
         # retrieve -name ...
         if not self.vodinfos:
            return []

         path_list = []
         for _, vodinfo in self.vodinfos.vodinfo_table.iterrows():
            path_list = path_list + list(map(lambda uri, name=vodinfo["device_name"]: name+uri, vodinfo['uri_list']))

         self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ n for n in path_list if n.startswith(text) ]}')
         return [ n for n in path_list if n.startswith(text) ]
      elif self.current_token.cmd_str == '-id':
         # retrieve -id ...
         if not self.vodinfos:
            return []

         path_list = []
         for _, vodinfo in self.vodinfos.vodinfo_table.iterrows():
            path_list = path_list + list(map(lambda uri, id=vodinfo["di"]: id+uri, vodinfo['uri_list']))

         self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ n for n in path_list if n.startswith(text) ]}')
         return [ n for n in path_list if n.startswith(text) ]
      else:
         return []


   def _cb_parse_retrieve(self, arg: Option, value: list[str], cli_mgr: object = None) -> int:
      """_cb_parse_retrieve() : parse `value`, save it in arg.value if it is valid, and return result

      Args:
         token (Option): current target argument (`Command` or `Option`) that takes `value` as its parameter value
         value (list): all remaining string after this [Sub]Command which calls this parser

      Returns:
          int: `>=0`: the number of tokens to be skpped next turn
               `< 0`: parse error!
      """
      value_exp = " ".join(value)
      # evaluate if this value has correct format...
      result, _, _ = arg._validate_value(value_exp, True)
      if result:
         # store parameter value for firing the whole command...
         arg.value = value_exp
         return len(value)
      else:
         return -1



   # --------------------------------------------------------------------------
   # bridge> update ...
   # --------------------------------------------------------------------------
   # bridge> update -name ...
   # update -name <device_name>/<resource_path> { property1:<value>, property2:<value>, ...  }
   # --------------------------------------------------------------------------
   # bridge> update -id ...
   # update -id <device_id>/<resource_path> { property1:<value>, property2:<value>, ...  }
   # --------------------------------------------------------------------------

   def _cb_action_update(self, cli_mgr: object) -> bool:
      """_cb_action_update(): callback for running "update" command

      Args:
         cli_mgr (object): CliManager instance

      Returns:
         bool: running result
      """
      if not cli_mgr.vodinfos:
         self.logger.error('vodinfo table has not been initialized, do "vod list" first!')
         return False

      vod_table = cli_mgr.vodinfos.vodinfo_table
      option_list = cli_mgr.current_parsed_command['options']

      # check existence of value for each option
      for option in option_list:
         if option.re and not option.value:
            cli_mgr.logger.error(f'required parameter values of "{option.cmd_str}" are missing!')
            return False

      if len(option_list) != 2 or ((option_list[0].cmd_str != '-name' and option_list[0].cmd_str != '-id') or option_list[1].cmd_str != '-value'):
         cli_mgr.logger.error('update command requires 2 options: -name/-id, -value')
         return False

      # convert VOD name into VOD ID
      result, cli_mgr.current_parsed_command['options'], vod_econame = self._convert_name_to_id(option_list, vod_table)
      if not result:
         return False

      # specify which ecosystem this VOD belongs to..
      cli_mgr.current_parsed_command['econame'] = vod_econame

      if lib.update(cli_mgr._parsed_command_dumps(cli_mgr.current_parsed_command)) < 0:
         return False

      return True


   def _cb_generator_update(self, text: str, cli_mgr: object = None) -> list[str]:
      """_cb_generator_update() : generate string list starting with "text" substring

      Args:
         text (str): substring which is being input

      Returns:
         list[str]: list of candidate string starting with "text"
      """
      if self.current_token.cmd_str == 'update':
         # update ...
         self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ n for n in list(self.command_list["update"].options) if n.startswith(text) ]}')
         return [ n for n in list(self.command_list["update"].options) if n.startswith(text) ]
      elif self.current_token.cmd_str == '-name':
         # update -name ...
         if not self.vodinfos:
            return []

         path_list = []
         for _, vodinfo in self.vodinfos.vodinfo_table.iterrows():
            path_list = path_list + list(map(lambda uri, name=vodinfo["device_name"]: name+uri, vodinfo['uri_list']))

         self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ n for n in path_list if n.startswith(text) ]}')
         return [ n for n in path_list if n.startswith(text) ]
      elif self.current_token.cmd_str == '-id':
         # update -id ...
         if not self.vodinfos:
            return []

         path_list = []
         for _, vodinfo in self.vodinfos.vodinfo_table.iterrows():
            path_list = path_list + list(map(lambda uri, id=vodinfo["di"]: id+uri, vodinfo['uri_list']))

         self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ n for n in path_list if n.startswith(text) ]}')
         return [ n for n in path_list if n.startswith(text) ]
      else:
         return []


   def _cb_parse_update(self, arg: Option, value: list[str], cli_mgr: object = None) -> int:
      """_cb_parse_update() : parse `value`, save it in arg.value if it is valid, and return result

      Args:
         token (Option): current target argument (`Command` or `Option`) that takes `value` as its parameter value
         value (list): all remaining string after this [Sub]Command which calls this parser

      Returns:
          int: `>=0`: the number of tokens to be skpped next turn
               `< 0`: parse error!
      """
      value_exp = " ".join(value)
      # evaluate if this value has correct format...
      if arg.re == 'json':
         # special case: json option value should be last one
         result, _, _ = arg._validate_value(value_exp, True)
         if result:
            value_exp = loads(value_exp) # store as json object itself...
            consumed_tokens = len(value)
      else:
         self.logger.debug(f'value_exp: {value_exp}')
         result, _, end_index = arg._validate_value(value_exp, False)

         if result:
            self.logger.debug(f'result: {result}, end_index: {end_index}')
            consumed_tokens = len(value) - len(value_exp[end_index:].split())
            self.logger.debug(f'remaining value_exp: {value_exp[end_index:]}, total number of tokens: {len(value)}, consumed_tokens: {consumed_tokens}')
            value_exp = value_exp[0:end_index].strip()

      if result:
         # store parameter value for firing the whole command...
         arg.value = value_exp
         self.logger.debug(f'Parameter value for "{arg.cmd_str}" : {arg.value}')
         return consumed_tokens
      else:
         if arg.re == 'json':
            self.logger.error('"-value" parsing error: json syntax error or "-value" option should be last option')
         return -1



   # --------------------------------------------------------------------------
   # bridge> help ...
   # help cd, help retrieve, ...
   # --------------------------------------------------------------------------

   def _cb_action_help(self, cli_mgr: object) -> bool:
      """_cb_action_help(): callback for running "help" command

      Args:
          cli_mgr (object): CliManager instance

      Returns:
          bool: running result
      """
      all_cmds = { **self.command_list, **(self.eco_command_list[self.current_econame] if self.current_econame else {}) }
      cli_mgr.logger.debug(f'value: {cli_mgr.current_parsed_command["cmd"].value}, all_cmds: {list(all_cmds)}')

      if cli_mgr.current_parsed_command['cmd'].value and (not set(cli_mgr.current_parsed_command['cmd'].value).issubset(list(all_cmds))):
         return False

      print('\n  \033[94mhit "tab" to see current candidate values while typing command\033[m')
      if not cli_mgr.current_parsed_command['cmd'].value:
         # print helps for all available commands
         for cmd_str in list(all_cmds):
            print(f'\n  \033[36m{all_cmds[cmd_str].help}\033[m')
      else:
         # print help for specific commands
         for cmd_str in cli_mgr.current_parsed_command['cmd'].value:
            print(f'\n  \033[36m{all_cmds[cmd_str].help}\033[m')

      return True


   def _cb_generator_help(self, text: str, cli_mgr: object = None) -> list[str]:
      """_cb_generator_help() : generate string list starting with "text" substring

      Args:
         text (str): substring which is being input

      Returns:
         list[str]: list of candidate string starting with "text"
      """
      if self.current_token.cmd_str == 'help':
         # help <command>
         self.token_candidate_list = [ n for n in list(self.command_list) + (list(self.eco_command_list[self.current_econame]) if self.current_econame else []) if n.startswith(text) ]
         self.logger.debug(f'Generating cadidate list: partial string: "{text}", candidates: {[ n for n in list(self.command_list) + (list(self.eco_command_list[self.current_econame]) if self.current_econame else [] ) if n.startswith(text) ]}')
         return [ n for n in list(self.command_list) + (list(self.eco_command_list[self.current_econame]) if self.current_econame else []) if n.startswith(text) ]
      else:
         return []


   def _cb_parse_help(self, arg: Option, value: list[str], cli_mgr: object = None) -> int:
      """_cb_parse_help() : parse `value`, save it in `arg.value` if it is valid, and return result

      Args:
         token (Option): current target argument (`Command` or `Option`) that takes `value` as its parameter value
         value (list): all remaining string after this [Sub]Command which calls this parser

      Returns:
          int: `>=0`: the number of tokens to be skpped next turn
               `< 0`: parse error!
      """
      # e.g.) help module
      value_exp = " ".join(value)
      # evaluate if this value has correct format...
      result, _, _ = arg._validate_value(value_exp, True)
      if result:
         # store parameter value for firing the whole command...
         arg.value = value
         return len(value)
      else:
         return -1


   def _scan_ecosystem_modules(self) -> list:
      """_scan_ecosystem_modules() : scan current available ecosystem module list

      Returns:
         list : list of current available ecosystem translation modules
      """
      current_dir = os.path.dirname(os.path.abspath(__file__))
      plugins_dir = current_dir + os.sep + 'plugins'
      plugin_dirs = [f for f in os.scandir(plugins_dir) if f.is_dir()]

      return plugin_dirs


   def load_ecosystem_commands(self) -> None:
      """load_ecosystem_commands() : load CLI commands for each ecosystems
      """
      try:
         plugin_dirs = self._scan_ecosystem_modules()
         if (not plugin_dirs):
            raise RuntimeError('no ecosystem translation module exits!')

         for d in plugin_dirs:
            plugin_module = importlib.import_module('plugins.'+d.name+'.cli')
            plugin_commands = getattr(plugin_module, 'commands')
            self.eco_command_list[d.name] = plugin_commands
      except BaseException as e:
         self.logger.error(e)
         sys.exit(1)


   def _reset_parsed_commands(self) -> None:
      """_reset_parsed_commands() : reset current_parsed_command list
      """

      # clear values stored in previous command string evaluation phase (_eval_cmd())
      # - while evaluating command string, parsed parameter value(s) of subcommand or option will be stored in "value" field.
      #   so, "value" filed should be cleared for next command evaluation.
      for _, v in self.current_parsed_command.items():
         if isinstance(v, list):
            for n in v:
               n.value = None
         elif isinstance(v, Option) or isinstance(v, Command):
            v.value = None
         else:
            v = None

      self.current_parsed_command = { 'cmd': None, 'subcmd': None, 'options' : [] , 'econame' : None }
      self.current_token = None
      self.token_candidate_list = []


   def _parse_value(self, arg: Option, value: list[str]) -> int:
      """_parse_value() : parse `value` and store it to `arg.value` if there is no error

      Args:
          arg (Option): Option/[Sub]Command which takes `value` as its parameter value
          value (list[str]): value to be parsed

      Returns:
          int: number of tokens to be skipped
      """
      if value:
         self.logger.debug(f'value: {value}')
         if (arg.re):
            n = arg.parse(arg, value, self)
            return n

      self.logger.debug(f'Paramter value is being typed or "{arg.cmd_str}" requires no parameter value, so this is not error situation..')
      return 0


   def _eval_options_find_cmd_option(self, i: int, current_option_set: dict) -> (bool, dict):
      """_eval_options_find_cmd_option() : find available option set (dict) for command

      Args:
         i (int): index of option in token list of commnad string
         current_option_set (dict): dict of options that command which is being evaluated supports

      Returns:
         tuple: evaluation result, current_option_set
      """
      if self.command_tokens[i] in self.current_parsed_command['cmd'].options:
         self.current_parsed_command['options'].append(self.current_parsed_command['cmd'].options[self.command_tokens[i]])
         self.current_token = self.current_parsed_command['options'][-1]
         current_option_set = self.current_parsed_command['cmd'].options
         self.logger.debug(f'{current_option_set} (options of command: "{self.current_parsed_command["cmd"].cmd_str}") is stored to current_option_set!')
      else:
         self.logger.error(f'"{self.command_tokens[i]}": unexpected option! {self.current_parsed_command["cmd"].cmd_str} doesn\'t support this option!')
         return (False, current_option_set)
      self.logger.debug(f'Candidate option list: {list(self.current_parsed_command["cmd"].options)}')
      self.logger.debug(f'Identified current option: {self.current_parsed_command["options"][-1].cmd_str}')

      return (True, current_option_set)


   def _eval_options_find_subcmd_option(self, i: int, current_option_set: dict) -> (bool, dict):
      """_eval_options_find_subcmd_option() : find available option set (dict) for sub-command

      Args:
         i (int): index of option in token list of commnad string
         current_option_set (dict): dict of options that sub-command which is being evaluated supports

      Returns:
         tuple: evaluation result, current_option_set
      """
      if i > 1:
         if self.current_parsed_command['subcmd'].options:
            # if command substring is: "cmd subcmd [-option [-option] .. ]"
            # => if identified SUB-COMMAND has OPTION
            # => store options of current SUB-COMMAND
            if self.command_tokens[i] in self.current_parsed_command['subcmd'].options:
               self.current_parsed_command['options'].append(self.current_parsed_command['subcmd'].options[self.command_tokens[i]])
               self.current_token = self.current_parsed_command['options'][-1]
               current_option_set = self.current_parsed_command['subcmd'].options
               self.logger.debug(f'{current_option_set} (options of subcommand: "{self.current_parsed_command["subcmd"].cmd_str}") is stored to current_option_set!')
            else:
               self.logger.error(f'"{self.command_tokens[i]}": unexpected option! {self.current_parsed_command["subcmd"].cmd_str}! doesn\'t support this option!')
               return (False, current_option_set)
            self.logger.debug(f'Candidate option list: {list(self.current_parsed_command["subcmd"].options)}')
            self.logger.debug(f'Identified current option: {self.current_parsed_command["options"][-1].cmd_str}')
         else:
            # if identified SUB-COMMAND has no OPTION, but there are still another arguments.. => error!
            self.logger.error(f'"{self.command_tokens[i]}": unexpected option! {self.current_parsed_command["subcmd"].cmd_str} supports no option!')
            return (False, current_option_set)
      return (True, current_option_set)


   def _eval_options_find_optionset(self, i: int, current_option_set: dict) -> (bool, dict):
      """_eval_options_find_optionset() : find available option set (dict) for command or sub-command

      Args:
         i (int): index of option in token list of commnad string
         current_option_set (dict): dict of options that command (or sub-command) which is being evaluated supports

      Returns:
         tuple: evaluation result, current_option_set
      """
      # decide what "current_option_set" is..
      if self.current_parsed_command['cmd']:
         # if command substring is: "cmd .."
         # => if there is an identified COMMAND
         if self.current_parsed_command['subcmd']:
            # if command substring is: "cmd subcmd .."
            # => if identified COMMAND has SUB-COMMAND
            result, current_option_set = self._eval_options_find_subcmd_option(i, current_option_set)
            if not result:
               return (False, current_option_set)
         elif self.current_parsed_command['cmd'].options:
            # i == 1 : the case that a command has no sub-command but has options..
            #
            # if command substring is: "cmd -option .. [-option [-option] .. ]"
            # => if identified COMMAND has no SUB-COMMAND, and has OPTIONS:
            # => store options of current command
            result, current_option_set = self._eval_options_find_cmd_option(i, current_option_set)
            if not result:
               return (False, current_option_set)
         else:
            # if identifed COMMAND has no OPTIONS, but there are still another arguments.. => error!
            # self.current_parsed_command['options'] = []
            self.logger.error(f'"{self.command_tokens[i]}": unexpected option! {self.current_parsed_command["cmd"].cmd_str} supports no option!')
            return (False, current_option_set)
      return (True, current_option_set)


   def _eval_options(self, i: int, current_option_set: dict) -> (bool, dict):
      """_eval_options() : evaluate options

      Args:
         i (int): index of option in token list of commnad string
         current_option_set (dict): dict of options that command (or sub-command) which is being evaluated supports

      Returns:
         tuple: evaluation result, current_option_set
      """
      # 3. evaluate options (i == 1 : the case that "main command" has no sub-command, but options)
      # options..
      if current_option_set:
         self.logger.debug(f'current_option_set : {current_option_set}')
         if self.command_tokens[i] in current_option_set:
            self.current_parsed_command['options'].append(current_option_set[self.command_tokens[i]])
            self.current_token = self.current_parsed_command['options'][-1]
         else:
            self.logger.debug(f'"{self.command_tokens[i]}": unexpected option! {self.current_parsed_command["cmd"].cmd_str}! doesn\'t support this option!')
            return (False, current_option_set)
      else:
         self.logger.debug('current_option_set is NULL!')
         # try to find optionset for the current identified "main command" or "sub-command"
         result, current_option_set = self._eval_options_find_optionset(i, current_option_set)
         if not result:
            return (False, current_option_set)
      return (True, current_option_set)


   def _eval_sub_cmd(self, i: int) -> bool:
      """_eval_sub_cmd() : evaluation sub-command (and it values)

      Args:
         i (int): index of sub-command in token list of commnad string

      Returns:
         bool: operation result
      """
      # 2. evaluate sub-command
      # subcommand or options..
      if self.current_parsed_command['cmd']:
         if self.current_parsed_command['cmd'].sub_cmds:
            # sub-command..
            if self.command_tokens[i] in self.current_parsed_command['cmd'].sub_cmds:
               self.current_parsed_command['subcmd'] = self.current_parsed_command['cmd'].sub_cmds[self.command_tokens[i]]
               self.logger.debug(f'Candidate subcommand list: {list(self.current_parsed_command["cmd"].sub_cmds)}')
               self.logger.debug(f'Identified subcommand: {self.current_parsed_command["subcmd"].cmd_str}')
               self.current_token = self.current_parsed_command['subcmd']
            elif self.current_parsed_command['cmd'].sub_cmds_optional == False:
               # check if this COMMAND has optional SUB-COMMAND...
               # if not, it is error case!
               self.logger.error(f'"{self.command_tokens[i]}": unexpected or sub-command is missing!')
               return False
         # option case will be handled in "_eval_options()"...
      return True


   def _eval_main_cmd(self, i: int) -> bool:
      """_eval_main_cmd() : evaluation main command (and its values)

      Args:
         i (int): index of sub-command in token list of commnad string

      Returns:
         bool: operation result
      """
      # 1. evaluate main command
      # main command
      if self.command_tokens[i] in self.command_list:
         # check common commands list
         self.current_parsed_command['cmd'] = self.command_list[self.command_tokens[i]]
         self.logger.debug(f'Candidate commands list: {list(self.command_list)}')
         self.logger.debug(f'Identified command: {self.current_parsed_command["cmd"].cmd_str}')
      elif self.current_econame and (self.command_tokens[i] in self.eco_command_list[self.current_econame]):
         # check eco-specific commands list
         self.current_parsed_command['cmd'] = self.eco_command_list[self.current_econame][self.command_tokens[i]]
         self.logger.debug(f'Candidate "{self.current_econame}" commands list: {list(self.eco_command_list[self.current_econame])}')
         self.logger.debug(f'Identified command: {self.current_parsed_command["cmd"].cmd_str}')
      else:
         self.logger.error(f'"{self.command_tokens[i]}": Unexpected command!')
         return False
      self.current_token = self.current_parsed_command['cmd']
      return True


   def _eval_final_check_subcmd_options(self) -> bool:
      """_eval_final_check_subcmd_options() : check if required sub-command and its options exist

      Returns:
          bool: operation result
      """
      # If this COMMAND has SUBCOMMAND..
      if self.current_parsed_command['cmd'].sub_cmds:
         # "sub_cmds_optional == False" is default setting, so we need to check if this COMMAND really has SUBCOMMAND..
         if not self.current_parsed_command['subcmd']:
            # This COMMAND should have SUBCOMMAND, but it doesn't => Failure
            self.logger.error(f'{self.current_parsed_command["cmd"].cmd_str} needs subcommand!')
            return False
         elif self.current_parsed_command['subcmd'].options:
            # This SUBCOMMAND has OPTIONS..
            if not self.current_parsed_command['options']:
               # This COMMAND should have SUBCOMMAND with OPTION, but it doesn't => Failure
               self.logger.error(f'{self.current_parsed_command["cmd"].cmd_str} {self.current_parsed_command["subcmd"].cmd_str} needs option!')
               return False
      # If this COMMAND has no SUBCOMMAND, but OPTIONS..
      elif self.current_parsed_command['cmd'].options:
         if not self.current_parsed_command['options']:
            # This COMMAND should have OPTIONS, but is doesn't => Failure
            self.logger.error(f'{self.current_parsed_command["cmd"].cmd_str} needs option!')
            return False
      return True


   def _eval_final_check_optional_subcmd_options(self) -> bool:
      """_eval_final_check_optional_subcmd() : check if required options for sub-command exist

      Returns:
          bool: operation result
      """
      # If this COMMAND has OPTIONAL SUBCOMMAND, but has SUBCOMMAND..
      if self.current_parsed_command['subcmd'].options:
         # This COMMAND has OPTIONS..
         if not self.current_parsed_command['options']:
            # This COMMAND should have SUBCOMMAND with OPTIONS, but is doesn't => Failure
            self.logger.error(f'{self.current_parsed_command["cmd"].cmd_str} {self.current_parsed_command["subcmd"].cmd_str} needs option!')
            return False
      return True


   def _eval_final_check_cmd_options(self) -> bool:
      """_eval_final_check_cmd_options() : check if required options for command exist

      Returns:
          bool: operation result
      """
      # If this COMMAND has OPTIONAL SUBCOMMAND and have No SUBCOMMAND, but has OPTIONS..
      if not self.current_parsed_command['options']:
         # This COMMAND should have OPTIONS, but is doesn't => Failure
         self.logger.error(f'{self.current_parsed_command["cmd"].cmd_str} needs option!')
         return False
      return True


   def _eval_final_check(self, whole_cmd: bool) -> bool:
      """_eval_final_check() : final check of command string

      Args:
         whole_cmd (bool): true: check whole command, false: no operation

      Returns:
         bool: operation result
      """

      if not whole_cmd:
         return True

      if self.current_parsed_command['cmd']:
         if self.current_parsed_command['cmd'].sub_cmds_optional == False:
            if not self._eval_final_check_subcmd_options():
               return False
         elif self.current_parsed_command['subcmd']:
            if not self._eval_final_check_optional_subcmd_options():
               return False
         elif self.current_parsed_command['cmd'].options:
            if not self._eval_final_check_cmd_options():
               return False
      return True


   def _eval_cmd(self, cmd_str: str, whole_cmd: bool = False) -> bool:
      """_eval_cmd(): evaluate leading part of command string

      Args:
         cmd_str (str): leading part of command string
         whole_cmd (str): True : evaluate whole command string
                        False : evaluate partial command string while completing commmand

      Raises:
         e: any error

      Returns:
         bool: False if there is any parsing error,
               if this function returns False, completer will not try completion
      """
      self.logger.debug(f'Current index: {get_begidx()}')

      # reset previous parsing result..
      self._reset_parsed_commands()
      current_option_set = None

      self.command_tokens = cmd_str.split()
      self.logger.debug(f'Tokens in command: {self.command_tokens}')

      i = 0
      while (i < len(self.command_tokens)):
         if ((i == 0) and (not self._eval_main_cmd(i))) or ((i == 1) and (not self._eval_sub_cmd(i))):
            # 1. evaluate "main command"
            # 2. evaluate "sub-command"
            return False

         if (i >= 1):
            # 3. evaluate "options" of "main command" or "sub-command" (i == 1 : the case that "main command" has no sub-command, but options)
            result, current_option_set = self._eval_options(i, current_option_set)
            if not result:
               return False

         # parse argument values for "command" / "sub-command" / "option"
         n = self._parse_value(self.current_token, self.command_tokens[i+1:])
         if n < 0:
            self.logger.error(f'"{" ".join(self.command_tokens[i+1:])}": parse error, not suitable parameter value for "{self.current_token.cmd_str}"')
            return False
         i = i + n + 1

      # Final check before firing command : if the WHOLE COMMAND STRING is typed correctly according to command configuration
      return self._eval_final_check(whole_cmd)


   def _completer_initialize_cmd(self, text: str, state: int) -> None:
      """_completer_initialize_cmd() : prepare all possible "commands"

      Args:
         text (str): text to be completed
         state (int): 0 -> first call, others -> successive call
      """
      # no COMMAND has been typed yet..
      self.token_candidate_list = [ n for n in list(self.command_list) + (list(self.eco_command_list[self.current_econame]) if self.current_econame else []) if n.startswith(text) ]
      self.logger.debug(f'{state}th candidate: "{self.token_candidate_list[0]}", token_candidate_list: {self.token_candidate_list}') if self.token_candidate_list else None


   def _completer_initialize_others(self, text: str, state: int) -> None:
      """_completer_initialize_others() : prepare all possible other tokens except for "command"

      Args:
         text (str): text to be completed
         state (int): 0 -> first call, others -> successive call
      """
      # "self.current_token" has last identified "command" / "sub-command" / "option"
      # COMMAND, or SUB-COMMAND has been identified:
      if self.current_token.generator and (self.current_token.value == None or isinstance(self.current_token.value, list) or (self.current_token in self.current_parsed_command['options'])):
         # case 1) self.current_token.value == None: current_token(last reviewed token) has no parameter value, or parameter value is being inputted.
         # case 2) self.current_token.value != None, and self.current_token.value is "list" : current token could have one or more values (e.g. vod list <index0>, <index1>, ,... )
         # case 3) self.current_token.value != None, and self.current_token.value is NOT "list", and self.current_token is one of OPTIONS : current (last identified) token is OPTION, so more OPTION could follow..
         if self.current_token.value != None and self.current_token in self.current_parsed_command['options']:
            self.current_token = self.current_parsed_command['subcmd'] if self.current_parsed_command['subcmd'] != None else self.current_parsed_command['cmd']

         self.token_candidate_list = self.current_token.generator(text, self)
         self.logger.debug(f'{state}th candidate: "{self.token_candidate_list[0]}", token_candidate_list: {self.token_candidate_list}') if self.token_candidate_list else None
      else:
         # self.current_token.value != None: current_token(last reviewed token) has parameter value, and parameter value has been identified.
         self.token_candidate_list = []


   def _completer_initialize(self, text: str, state: int) -> bool:
      """_completer_initial_state() : prepare all possible tokens

      Args:
         text (str): text to be completed
         state (int): 0 -> first call, others -> successive call

      Returns:
         bool: operation result
      """
      self._reset_parsed_commands()

      # parse sub-string preceding current cursor position..
      if self._eval_cmd(get_line_buffer()[0:get_begidx()]) == False:
         self.logger.error('Input command parsing error!')
         return False

      self.logger.debug(f'Current parsed commands: { [ list(map(lambda x: (x.cmd_str, x.value), n)) if isinstance(n, list) else (n.cmd_str, n.value) if n != None else "" for n in self.current_parsed_command.values() ] }')
      self.logger.debug(f'Last evaluated token: {self.current_token.cmd_str if self.current_token else "None"}')

      if not self.current_token:
         # if no token has been identified yet, try to create candidate list of "main command"
         self._completer_initialize_cmd(text, state)
      else:
         # else, try to create candidate list of "sub-command" or "option" or "values"
         self._completer_initialize_others(text, state)

      return True


   def _completer(self, text: str, state: int) -> str:
      """_completer() : custom readline completer

      Args:
         text (str): text to be completed
         state (int): 0 -> first call, others -> successive call

      Returns:
         str: completed string
      """
      self.logger.debug(f'=> Current Values - text: "{text}", state: {state}, rl_line_buf: "{get_line_buffer()}", start: {get_begidx()}, end: {get_endidx()}')

      try:
         if (state == 0):
            if not self._completer_initialize(text, state):
               return None
            return self.token_candidate_list.pop(0) if self.token_candidate_list else None
         else:
            # state > 0
            # continue to pop and return next candidate token from list
            self.logger.debug(f'{state}th candidate: "{self.token_candidate_list[0]}", token_candidate_list : {self.token_candidate_list}') if self.token_candidate_list else None
            return self.token_candidate_list.pop(0) if self.token_candidate_list else None
      except BaseException as e:
         cli_log()
         raise e


   @staticmethod
   def ffi_str_to_cstr(string: str):
      """ffi_str_to_cstr() : convert python str to cdata string

      Args:
         string (str): python string to be converted to cdata string

      Returns:
         cdata string: converted cdata string
      """
      return ffi.new('char[]', string)


   @staticmethod
   def ffi_strarray_to_cstrarray(strarray: list[str]):
      """ffi_strarray_to_cstrarray() : convert python str array to cdata string array

      Args:
         strarray (list[str]): python str array to be converted to cdata string array

      Returns:
         cdata string array: converted cdata string array
      """
      byte_strarray = [ n.encode() for n in strarray ]
      return ffi.new('char *[]', [ ffi.new('char[]', n) for n in byte_strarray ])

   def initialize(self) -> None:
      """initialize() : initialize CLI
      """

      try:
         # === initialize rl ===
         # register ecosystem specific commands list
         self.load_ecosystem_commands()

         for k, v in self.eco_command_list.items():
            self.logger.debug(f'Ecosystem commands for "{k}": {list(v)}')

         # allows only "tab" and "space" as separator
         # - to remove some delimiters from existing set, use this code : set_completer_delims(get_completer_delims().replace('/', '')) 
         set_completer_delims('\t ')
         self.logger.debug(f'current delimiters: "{get_completer_delims()}"')

         # configure custom completer
         set_completer(self._completer)

         # configure complete key
         parse_and_bind('tab: complete')

         # initialize bridge manager
         lib.init_bridge_manager()

         # XXX for testing...
         # lib.add_vods_test()
      except BaseException as e:
         raise e


   def shutdown(self) -> None:
      # === shutdown bridge manager module ===
      lib.shutdown_bridge_manager()


   def fire_command(self, cmd_str: str) -> bool:
      """fire_command() : run command string

      Args:
         cmd_str (str): command string which is read from console

      Raises:
         CliRunError: runtime error log object

      Returns:
         bool: run result
      """
      self.logger.debug(f'input command: "{cmd_str}"')

      if self._eval_cmd(cmd_str, True) == False:
         raise CliRunError(f'Parsing "{cmd_str}" failed!')

      if self.current_parsed_command['cmd'] and self.current_parsed_command['cmd'].action:
         if self.current_parsed_command['cmd'].action(self) == False:
            raise CliRunError(f'Running "{cmd_str}" failed!')


   def run(self) -> None:
      """run() : start CLI main loop, and fire command
      """
      while (True):
         try:
            self._reset_parsed_commands()
            cmd_str = input(self.current_prompt)
            self.fire_command(cmd_str)
         except CliRunError as e:
            print(e)
         except BaseException as e:
            raise e


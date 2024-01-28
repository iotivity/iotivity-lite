#============================================================================
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
#============================================================================


from bridge_manager import ffi, lib
from typing import Callable
from pandas import DataFrame, concat
from iotivity import Iotivity as iot
from json import loads, dumps


class VodManager:
   """maintains VOD info list
   
   Attributes:
      vodinfo_table (DataFrame): keeps VOD info (columns: VOD property (e.g. di, device_name, ...))
   """
   def __init__(self, json_vodinfo_list: str) -> None:
      self.vodinfo_table = DataFrame(columns=['di', 'device_name', 'ep_list', 'uri_list', 'econame', 'is_online'])
      self.vodinfo_table['is_online'] = self.vodinfo_table['is_online'].astype(bool)
      
      vodinfo_list = loads(ffi.string(json_vodinfo_list))
      for vodinfo_item in vodinfo_list:
         new_row = { 'di': [vodinfo_item['di']], 
                    'device_name': [vodinfo_item['device_name']],
                    'ep_list': [vodinfo_item['ep_list']],
                    'uri_list': [vodinfo_item['uri_list']],
                    'econame': [vodinfo_item['econame']],
                    'is_online': [vodinfo_item['is_online']]}
         self.vodinfo_table = concat([self.vodinfo_table, DataFrame(new_row)], ignore_index=True)
   
   def __repr__(self) -> str:
      return repr(self.vodinfo_table)


class VodInfo:
   def __init__(self, vodinfo_list) -> None:
      self.vodinfo_list = dict()
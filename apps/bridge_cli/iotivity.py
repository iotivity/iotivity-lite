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


class Iotivity:
   # ----------------------------------------------------------------
   # python <- C
   # ----------------------------------------------------------------
   @staticmethod
   def str_from_string(char_str) -> str:
      """str_from_string(): C-string => python str

      Args:
         char_str (C-string): C string

      Returns:
         str: unicode string converted from C-string
      """
      return str(ffi.string(char_str), encoding='utf-8')
      
   @staticmethod
   def str_from_ocstr(oc_str) -> str:
      """str_from_ocstr(): oc_string => python str

      Args:
         oc_str (oc_string): oc_string

      Returns:
         str: unicode string converted from oc_string string
      """
      return str(ffi.string(ffi.cast('char *', oc_str.ptr)), encoding='utf-8')
   
   @staticmethod
   def strlist_from_ocstrlist(list_item) -> list[str]:
      """strlist_from_ocstrlist(): oc string list (str_node_t) => python str list

      Args:
         list_item (struct list *): pointer of list head

      Returns:
         list[str]: str list
      """
      str_list = []
      item = ffi.cast("str_node_t *", list_item)
      while(item):
         str_list.append(str(ffi.string(ffi.cast('char *', item.str.ptr)), encoding="utf-8"))
         item = item.next
      return str_list
   
   @staticmethod
   def bool_from_ocbool(var) -> bool:
      """bool_from_ocbool(): C bool => python bool

      Args:
          var (bool): bool variable

      Returns:
          bool: bool var
      """
      return bool(ffi.cast('bool', var))
   
   # ----------------------------------------------------------------
   # python -> C
   # ----------------------------------------------------------------
   @staticmethod
   def str_to_string(var):
      """str_to_string(): python str => "C char[]"

      Args:
         var (str): python str var

      Returns:
         char[]: char[] var
      """
      return ffi.new('char[]', var.encode())
   
   @staticmethod
   def strlist_to_strarray(str_list: list):
      """strlist_to_strarray(): python str list => "C char *array[]"

      Args:
         str_list (list): python str list
          
      Returns:
         (number of array, C char *array[]) : (number of array, char *array[])
      """
      array_len = len(str_list)
      return (array_len, ffi.new('char *[]', [ ffi.new('char[]', m) for m in [ n.encode() for n in str_list ] ]))
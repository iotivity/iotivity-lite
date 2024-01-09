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

import inspect
import traceback as tb


def f_name() -> str:
   """f_name : return function name of caller

   Returns:
       str: function name
   """
   return inspect.stack()[2].function


def cli_log():
   print(f'\n==================================================>\n{tb.format_exc()}==================================================>')
   
   
class CliRunError(Exception):
   """CliRunError used to show runtime error message
   """
   def __init__(self, *args: object) -> None:
      super().__init__(*args)
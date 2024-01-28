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

from cli_manager import CliManager
from debug import cli_log, CliRunError
from argparse import ArgumentParser
from logging import DEBUG, WARNING, ERROR

def main():
   try:
      arg_parser = ArgumentParser(description='bridge CLI')
      arg_parser.add_argument('-d', action='store_true', help='print log message')
      
      cli_manager = CliManager(arg_parser.parse_args().d)
      cli_manager.initialize()
      cli_manager.run()
   except SystemExit as e:
      raise e
   except (EOFError, KeyboardInterrupt):
      cli_manager.shutdown()
   except BaseException:
      cli_log()
      cli_manager.shutdown()


if (__name__ == "__main__"):
   main()

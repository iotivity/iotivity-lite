# ============================================================================
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
# ============================================================================

from typing import Callable
from json import loads, JSONDecodeError
import re


class Option:
    """Option
    a CLI option

    Attributes:
       cmd_str (str) : option command string
       re (raw string) : regular expression for parsing
       parse (function) : parser for this command string
       generator (function) : candidate generator for this option
       value (list) : store parsed value for this Option/(Sub)Command
       help (str) : usage string for this Option/[Sub]Command
    """

    # def __init__(self, cmd_str: str, re: str = None,  parse: callable[[], None] = None, generator: callable[[], None] = None) -> None:
    def __init__(
        self,
        cmd_str: str,
        re: str = None,
        parse: callable = None,
        generator: callable = None,
        help: str = "",
    ) -> None:
        self.cmd_str = cmd_str
        self.re = re
        self.parse = parse
        self.generator = generator
        self.value = None
        self.help = help

    def __repr__(self) -> str:
        return f"Option({self.cmd_str}, {self.re}, {self.parse}, {self.generator}, {self.value})"

    def _validate_value(self, value: str, is_whole: bool) -> tuple:
        """validate_value() : validate if `value` is the right value for this Option/[Sub]Command

        Args:
            value (str): parameter value for this Option/[Sub]Command
            is_whole (bool): True: compare whole remaining `value`
                             False: compare leading part of `value`

        Returns:
            tuple: (result, start, end)
                    result: True if the value is verified
                    start: start index of matched (sub)string
                    end: end index of matched (sub)string
        """
        if self.re:
            if self.re == "json":
                # special case for json string
                if is_whole == False:
                    # json option should be the last option...
                    return (False, 0, 0)
                else:
                    try:
                        # try to test if json string is correct...
                        loads(value)
                        return (True, 0, len(value))
                    except JSONDecodeError as e:
                        print(e)
                        return (False, 0, 0)
            else:
                result = re.match(self.re, value)
                if is_whole:
                    return (
                        lambda r, v: (
                            (r.start() == 0 and r.end() == len(v)),
                            r.start(),
                            r.end(),
                        )
                        if r
                        else (False, 0, 0)
                    )(result, value)
                else:
                    return (
                        lambda r, v: (r.start() == 0, r.start(), r.end())
                        if r
                        else (False, 0, 0)
                    )(result, value)
        else:
            return (False, 0, 0)


class Command(Option):
    """Command (command_string, [sub command list], [option list])
    a CLI (sub)command

    Attributes:
       sub_cmds (dict) : sub commands of this command
       sub_cmds_optional (bool) : set True, if this command has optional sub-commands
       options (dict) : options for this command
       action (function) : operation for this command
    """

    # def __init__(self, cmd_str,  re: str = None, sub_cmds: dict = None, options: dict = None,
    #              action: callable[[], None] = None, parse: callable[[], None] = None,
    #              generator: callable[[], None] = None) -> None:
    def __init__(
        self,
        cmd_str,
        sub_cmds_optional: bool = False,
        re: str = None,
        sub_cmds: dict = None,
        options: dict = None,
        action: callable = None,
        parse: callable = None,
        generator: callable = None,
        help: str = "",
    ) -> None:
        super().__init__(cmd_str, re, parse, generator)

        self.sub_cmds_optional = sub_cmds_optional
        self.sub_cmds = sub_cmds
        self.options = options
        self.action = action
        self.help = help

    def __repr__(self) -> str:
        return f"Command({self.cmd_str}, {self.re}, {self.sub_cmds}, \
         {self.options}, {self.action}, {self.parse}, \
         {self.generator}, {self.value})"
# ==============================================================================
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
# ==============================================================================

from common.command import Command, Option
from bridge_manager import ffi, lib
from cli_manager import CliManager

# =============================================================================
# define callback functions for Matter CLI Commands
# =============================================================================


# -----------------------------------------------------------------------------
# bridge/matter> discover ...
# -----------------------------------------------------------------------------
def _cb_action_discover(cli_mgr: CliManager) -> bool:
    """_cb_action_discover callback for running "discover" command

    Args:
       cli_mgr (CliManager): CliManager instance

    Returns:
       bool: running result
    """
    cli_mgr.current_parsed_command["econame"] = "matter"
    if (
        lib.run_ecosystem_command(
            cli_mgr._parsed_command_dumps(cli_mgr.current_parsed_command)
        )
        < 0
    ):
        return False
    else:
        return True


def _cb_generator_discover(text: str, cli_mgr: CliManager = None) -> list[str]:
    """_cb_generator_discover() : generate string list starting with "text" substring

    Args:
       text (str): substring which is being input

    Returns:
       list[str]: list of candidate string starting with "text"
    """
    if cli_mgr.current_token.cmd_str == "discover":
        # discover ...
        return [n for n in list(commands["discover"].sub_cmds) if n.startswith(text)]
    else:
        return []


# -----------------------------------------------------------------------------
# bridge/matter> pairing ...
# -----------------------------------------------------------------------------
def _cb_action_pairing(cli_mgr: CliManager) -> bool:
    """_cb_action_discover() : callback for running "pairing" command

    Args:
       cli_mgr (CliManager): CliManager instance

    Returns:
       bool: running result
    """
    if (
        cli_mgr.current_parsed_command["subcmd"].cmd_str == "onnetwork"
        or cli_mgr.current_parsed_command["subcmd"].cmd_str == "unpair"
    ) and (not cli_mgr.current_parsed_command["subcmd"].value):
        cli_mgr.logger.debug(
            f'required parameter values of "{cli_mgr.current_parsed_command["subcmd"].cmd_str}" are missing!'
        )
        return False

    cli_mgr.current_parsed_command["econame"] = "matter"
    if (
        lib.run_ecosystem_command(
            cli_mgr._parsed_command_dumps(cli_mgr.current_parsed_command)
        )
        < 0
    ):
        return False
    else:
        return True


def _cb_generator_pairing(text: str, cli_mgr: CliManager = None) -> list[str]:
    """_cb_generator_pairing() : generate string list starting with "text" substring

    Args:
       text (str): substring which is being input

    Returns:
       list[str]: list of candidate string starting with "text"
    """
    if cli_mgr.current_token.cmd_str == "pairing":
        return [n for n in list(commands["pairing"].sub_cmds) if n.startswith(text)]
    else:
        return []


# bridge/matter> pairing onnetwork ...
def _cb_parse_pairing(arg: Option, value: list[str], cli_mgr: CliManager = None) -> int:
    """_cb_parse_pairing() : parse `value`, save it in arg.value if it is valid, and return result

    Args:
       token (Option): current target argument (`Command` or `Option`) that takes `value` as its parameter value
       value (list): all remaining string after this [Sub]Command which calls this parser

    Returns:
       int: `>=0`: the number of tokens to be skpped next turn
            `< 0`: parse error!
    """
    # pairing onnetwork
    value_exp = " ".join(value)
    # evaluate if this value has correct format...
    result, _, _ = arg._validate_value(value_exp, True)
    if result:
        # store parameter value for firing the whole command...
        arg.value = value
        return len(value)
    else:
        return -1


# =============================================================================
# define CLI commands for Matter Plugin
# =============================================================================
discover_subcmds = {
    "list": Command("list"),
    "commissionables": Command("commissionables"),
    "commissioners": Command("commissioners"),
}

pairing_subcmds = {
    "onnetwork": Command(
        "onnetwork",
        re=r"\s*(0x[\da-fA-F]+|[\d]+)\s+(0x[\da-fA-F]+|[\d]+)\s*",
        parse=_cb_parse_pairing,
    ),
    "onnetwork-instance-name": Command(
        "onnetwork-instance-name",
        re=r"\s*(0x[\da-fA-F]+|[\d]+)\s+(0x[\da-fA-F]+|[\d]+)\s+([\da-fA-F]+|[\d]+)\s*",
        parse=_cb_parse_pairing,
    ),
    "unpair": Command(
        "unpair", re=r"\s*(0x[\da-fA-F]+|[\d]+)\s*", parse=_cb_parse_pairing
    ),
}

commands = {
    "discover": Command(
        "discover",
        sub_cmds=discover_subcmds,
        action=_cb_action_discover,
        generator=_cb_generator_discover,
        help="discover { commissionables | commissioners | list }\n    discover commissionable node, commissioner node",
    ),
    "pairing": Command(
        "pairing",
        sub_cmds=pairing_subcmds,
        action=_cb_action_pairing,
        generator=_cb_generator_pairing,
        help="pairing { onnetwork <node-id> <setup-pin-code> | onnetwork-instance-name <node-id> <setup-pin-code> <instance-name> | unpair <node-id> }\n    pair or unpair matter node",
    ),
}

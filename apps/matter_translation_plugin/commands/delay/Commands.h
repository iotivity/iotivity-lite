/*
 *   Copyright (c) 2022 Project CHIP Authors
 *   All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */

#pragma once

#include "commands/common/Commands.h"
#include "commands/delay/SleepCommand.h"
#include "commands/delay/WaitForCommissioneeCommand.h"

void registerCommandsDelay(Commands & commands, CredentialIssuerCommands * credsIssuerConfig)
{
    const char * clusterName      = "Delay";
    commands_list clusterCommands = {
        make_unique<SleepCommand>(credsIssuerConfig),               //
        make_unique<WaitForCommissioneeCommand>(credsIssuerConfig), //
    };

    commands.Register(clusterName, clusterCommands);
}

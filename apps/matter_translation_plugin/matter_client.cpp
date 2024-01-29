/****************************************************************************
 *
 *   Copyright (c) 2020 Project CHIP Authors
 *   Copyright (c) 2023 ETRI Joo-Chul Kevin Lee (rune@etri.re.kr)
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
 *
 ****************************************************************************/


#include "commands/common/Commands.h"
#include "commands/example/ExampleCredentialIssuerCommands.h"

#include "commands/discover/Commands.h"
#include "commands/interactive/Commands.h" /* importing this header is necessary for building.. */
#include "commands/pairing/Commands.h"
#include "commands/storage/Commands.h"

#if 0
/*
 * intentionally leave below header for future update and testing...
 */
#include "commands/group/Commands.h"
#include "commands/delay/Commands.h"
#include "commands/payload/Commands.h"
#endif

#include <zap-generated/cluster/Commands.h>

static ExampleCredentialIssuerCommands g_credIssuerCommands;
static Commands g_commands;

void
RegisterMatterCommand()
{
  registerCommandsDiscover(g_commands, &g_credIssuerCommands);
  registerCommandsInteractive(g_commands, &g_credIssuerCommands);
  registerCommandsPairing(g_commands, &g_credIssuerCommands);
  registerClusters(g_commands, &g_credIssuerCommands);
  registerCommandsStorage(g_commands);

#if 0
/*
 * intentiaonally leave below codes for future update and testing...
 */
  registerCommandsDelay(commands, &credIssuerCommands);
  registerCommandsPayload(commands);
  registerCommandsTests(commands, &credIssuerCommands);
  registerCommandsGroup(commands, &credIssuerCommands);
#endif

  return;
}

void
UnregisterMatterCommand()
{
  g_commands.UnRegister();
}

int
RunMatterCommand(int argc, char *argv[], Command::ClientInitState init_state) {
  return g_commands.Run(argc, argv, init_state);
}


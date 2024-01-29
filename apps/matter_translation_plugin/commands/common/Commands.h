/*
 *   Copyright (c) 2020 Project CHIP Authors
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

#ifdef CONFIG_USE_LOCAL_STORAGE
#include <controller/ExamplePersistentStorage.h>
#endif // CONFIG_USE_LOCAL_STORAGE

#include "Command.h"
#include <map>

class Commands
{
public:
    using CommandsVector = ::std::vector<std::unique_ptr<Command>>;

    void Register(const char * clusterName, commands_list commandsList);

#if OC_BRG
    void UnRegister(void);
    int Run(int argc, char ** argv, Command::ClientInitState init_state = Command::ClientInitState::COMMAND_INTERACTIVE_NORMAL);
#else
    int Run(int argc, char ** argv);
#endif
    int RunInteractive(const char * command);

private:
#if OC_BRG
    /*
     * <2023/11/13> RunCommand() : add additional parameter
     */
    CHIP_ERROR RunCommand(int argc, char ** argv, bool interactive = false, Command::ClientInitState init_state = Command::ClientInitState::COMMAND_INTERACTIVE_NORMAL);
#else
    /* original code */
    CHIP_ERROR RunCommand(int argc, char ** argv, bool interactive = false);
#endif

    std::map<std::string, CommandsVector>::iterator GetCluster(std::string clusterName);
    Command * GetCommand(CommandsVector & commands, std::string commandName);
    Command * GetGlobalCommand(CommandsVector & commands, std::string commandName, std::string attributeName);
    bool IsAttributeCommand(std::string commandName) const;
    bool IsEventCommand(std::string commandName) const;
    bool IsGlobalCommand(std::string commandName) const;

    void ShowClusters(std::string executable);
    void ShowCluster(std::string executable, std::string clusterName, CommandsVector & commands);
    void ShowClusterAttributes(std::string executable, std::string clusterName, std::string commandName, CommandsVector & commands);
    void ShowClusterEvents(std::string executable, std::string clusterName, std::string commandName, CommandsVector & commands);
    void ShowCommand(std::string executable, std::string clusterName, Command * command);

    bool DecodeArgumentsFromInteractiveMode(const char * command, std::vector<std::string> & args);
    bool DecodeArgumentsFromBase64EncodedJson(const char * encodedData, std::vector<std::string> & args);
    bool DecodeArgumentsFromStringStream(const char * command, std::vector<std::string> & args);

    std::map<std::string, CommandsVector> mClusters;
#ifdef CONFIG_USE_LOCAL_STORAGE
    PersistentStorage mStorage;
#endif // CONFIG_USE_LOCAL_STORAGE
};

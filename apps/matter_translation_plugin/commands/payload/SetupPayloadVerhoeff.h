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

#include "../common/Command.h"
#include <setup_payload/SetupPayload.h>

class SetupPayloadVerhoeffVerify : public Command
{
public:
    SetupPayloadVerhoeffVerify() : Command("verhoeff-verify")
    {
        AddArgument("payload", &mSetupCode);
        AddArgument("position", 0, UINT8_MAX, &mPos);
    }
    CHIP_ERROR Run() override;

private:
    char * mSetupCode;
    uint8_t mPos;
    bool Verify(std::string codeString);
};

class SetupPayloadVerhoeffGenerate : public Command
{
public:
    SetupPayloadVerhoeffGenerate() : Command("verhoeff-generate") { AddArgument("payload", &mSetupCode); }
    CHIP_ERROR Run() override;

private:
    char * mSetupCode;
    CHIP_ERROR GenerateChar(std::string codeString, char & generatedChar);
};

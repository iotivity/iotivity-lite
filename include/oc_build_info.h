/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

/**
 * @file oc_build_info.h
 *
 * Library and OCF version information.
 */
#ifndef OC_BUILD_INFO_H
#define OC_BUILD_INFO_H

/**
 * IoTivity-lite library
 */
#define IOTIVITY_LITE_VERSION_MAJOR 2
#define IOTIVITY_LITE_VERSION_MINOR 2
#define IOTIVITY_LITE_VERSION_PATCH 5
#define IOTIVITY_LITE_VERSION_BUILD 10

/**
 * The IoTivity-lite version number has the following structure:
 *    MMNNPPBB
 *    Major version | Minor version | Patch version | Build version
 */
#define IOTIVITY_LITE_VERSION 0x0202050A
#define IOTIVITY_LITE_VERSION_STRING "2.2.5.10"

/**
 * OCF Specification
 *
 * Version of the OCF Specification implemented by this version of
 * IoTivity-lite.
 */
#define OCF_SPECIFICATION_VERSION_MAJOR 2
#define OCF_SPECIFICATION_VERSION_MINOR 2
#define OCF_SPECIFICATION_VERSION_PATCH 5

/**
 * The OCF Specification version number has the following format:
 *    MMNNPP00
 *    Major version | Minor version | Patch version
 */
#define OCF_SPECIFICATION_VERSION 0x02020500
#define OCF_SPECIFICATION_VERSION_STRING "2.2.5"

#endif /* OC_BUILD_INFO_H */

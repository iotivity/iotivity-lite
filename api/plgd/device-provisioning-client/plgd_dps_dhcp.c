/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "plgd_dps_internal.h"
#include "plgd_dps_apis_internal.h"
#include "plgd_dps_context_internal.h"
#include "plgd_dps_dhcp_internal.h"
#include "plgd_dps_endpoints_internal.h"
#include "plgd_dps_log_internal.h" // DPS_DBG
#include "plgd_dps_provision_internal.h"
#include "plgd/plgd_dps.h" // plgd_dps_context_t

#include <assert.h>
#include <string.h>

// define default codes for vendor encapsulated options
enum {
  DHCP_OPTION_CODE_DPS_ENDPOINT = 200,
  DHCP_OPTION_CODE_DPS_CERTIFICATE_FINGERPRINT = 201,
  DHCP_OPTION_CODE_DPS_CERTIFICATE_FINGERPRINT_MD_TYPE = 202,
};

// NOLINTNEXTLINE(modernize-*)
#define MAX_DHCP_VENDOR_ENCAPSULATED_OPTION_BYTE_SIZE (255)

void
plgd_dps_dhcp_init(plgd_dps_dhcp_t *dhcp)
{
  assert(dhcp);
  dhcp->option_code_dps_endpoint = DHCP_OPTION_CODE_DPS_ENDPOINT;
  dhcp->option_code_dps_certificate_fingerprint =
    DHCP_OPTION_CODE_DPS_CERTIFICATE_FINGERPRINT;
  dhcp->option_code_dps_certificate_fingerprint_md_type =
    DHCP_OPTION_CODE_DPS_CERTIFICATE_FINGERPRINT_MD_TYPE;
}

void
plgd_dps_dhcp_set_vendor_encapsulated_option_code_dps_endpoint(
  plgd_dps_context_t *ctx, uint8_t code)
{
  assert(ctx);
  ctx->dhcp.option_code_dps_endpoint = code;
}

uint8_t
plgd_dps_dhcp_get_vendor_encapsulated_option_code_dps_endpoint(
  const plgd_dps_context_t *ctx)
{
  assert(ctx);
  return ctx->dhcp.option_code_dps_endpoint;
}

void
plgd_dps_dhcp_set_vendor_encapsulated_option_code_dps_certificate_fingerprint(
  plgd_dps_context_t *ctx, uint8_t code)
{
  assert(ctx);
  ctx->dhcp.option_code_dps_certificate_fingerprint = code;
}

uint8_t
plgd_dps_dhcp_get_vendor_encapsulated_option_code_dps_certificate_fingerprint(
  const plgd_dps_context_t *ctx)
{
  assert(ctx);
  return ctx->dhcp.option_code_dps_certificate_fingerprint;
}

static int
hexchar_to_decimal(char hex)
{
  if (hex >= '0' && hex <= '9') {
    return hex - '0';
  }
  if (hex >= 'A' && hex <= 'F') {
    return 10 + (hex - 'A'); // NOLINT(readability-magic-numbers)
  }
  if (hex >= 'a' && hex <= 'f') {
    return 10 + (hex - 'a'); // NOLINT(readability-magic-numbers)
  }
  return -1;
}

static ssize_t
hex_to_value(const char *data, size_t data_size, uint8_t *value)
{
  assert(data);
  assert(data_size > 0);
  assert(value);
  *value = 0;
  // number of bytes used - it can be 1 or 2 or 3
  ssize_t used = 0;
  for (size_t i = 0; i < data_size; i++) {
    char hexc = data[i];
    if (hexc == ':') {
      // end of hex value
      used += 1;
      return used;
    }
    int val = hexchar_to_decimal(hexc);
    if (val == -1) {
      DPS_ERR("invalid character in vendor encapsulated options %c", hexc);
      return -1;
    }
    if (i == 2) {
      // we have 2 chars, so we are done
      return used;
    }
    if (i == 1) {
      // we have 1 char, so shift it about 4 bits
      *value = (uint8_t)(*value << 4);
    }
    *value |= val;
    used += 1;
  }
  return used;
}

ssize_t
plgd_dps_hex_string_to_bytes(const char *isc_dhcp_vendor_encapsulated_options,
                             size_t isc_dhcp_vendor_encapsulated_options_size,
                             uint8_t *buffer, size_t buffer_size)
{
  assert(isc_dhcp_vendor_encapsulated_options);
  assert(isc_dhcp_vendor_encapsulated_options_size > 0);
  size_t needed = 0;
  if (buffer && buffer_size > 0) {
    memset(buffer, 0, buffer_size);
  }
  for (size_t i = 0; i < isc_dhcp_vendor_encapsulated_options_size;) {
    uint8_t val = 0;
    ssize_t used =
      hex_to_value(isc_dhcp_vendor_encapsulated_options + i,
                   isc_dhcp_vendor_encapsulated_options_size - i, &val);
    if (used < 0) {
      return -1;
    }
    if (buffer && (needed < buffer_size)) {
      buffer[needed] = val;
    }
    needed++;
    i += used;
  }
  return (ssize_t)needed;
}

typedef bool plgd_dps_dhcp_set_option_cbk_t(uint8_t option_code,
                                            const uint8_t *data,
                                            size_t data_size, void *user_data);

static bool
parse_option(uint8_t option_code, const uint8_t *data, size_t data_size,
             size_t *used, plgd_dps_dhcp_set_option_cbk_t set_option_cbk,
             void *user_data)
{
  assert(data);
  assert(data_size > 0);
  assert(used);
  if (data_size < 1) {
    return false;
  }
  size_t size = data[0];
  if (size > data_size - 1) {
    return false;
  }
  if (set_option_cbk != NULL &&
      !set_option_cbk(option_code, data + 1, size, user_data)) {
    return false;
  }
  *used = size + 1;
  return true;
}

static bool
plgd_dps_dhcp_set_option_cbk(uint8_t option_code, const uint8_t *data,
                             size_t data_size, void *user_data)
{
  assert(user_data != NULL);
  dhcp_parse_data_t *dpd = (dhcp_parse_data_t *)user_data;
  if (dpd->dhcp == NULL) {
    return false;
  }
  if (data_size == 0) {
    return false;
  }
  if (option_code == dpd->dhcp->option_code_dps_endpoint) {
    dpd->endpoint = data;
    dpd->endpoint_size = data_size;
    return true;
  }
  if (option_code == dpd->dhcp->option_code_dps_certificate_fingerprint) {
    dpd->certificate_fingerprint = data;
    dpd->certificate_fingerprint_size = data_size;
    return true;
  }
  if (option_code ==
      dpd->dhcp->option_code_dps_certificate_fingerprint_md_type) {
    dpd->certificate_fingerprint_md_type = data;
    dpd->certificate_fingerprint_md_type_size = data_size;
    return true;
  }
#if DPS_DBG_IS_ENABLED
  // GCOVR_EXCL_START
  char buf[256]; // NOLINT(readability-magic-numbers)
  size_t len = data_size > sizeof(buf) - 1 ? sizeof(buf) - 1 : data_size;
  memcpy(buf, data, len);
  buf[len] = 0;
  DPS_DBG("Unknown option code %d with data: %s", option_code, buf);
// GCOVR_EXCL_STOP
#endif /* DPS_DBG_IS_ENABLED */
  return false;
}

bool
dps_dhcp_parse_vendor_encapsulated_options(
  dhcp_parse_data_t *dhcp_parse_data,
  const uint8_t *vendor_encapsulated_options,
  size_t vendor_encapsulated_options_size)
{
  assert(dhcp_parse_data);
  assert(vendor_encapsulated_options);
  assert(vendor_encapsulated_options_size > 0);
  for (size_t i = 0; i + 1 < vendor_encapsulated_options_size;) {
    size_t used = 0;
    if (!parse_option(vendor_encapsulated_options[i],
                      vendor_encapsulated_options + i + 1,
                      vendor_encapsulated_options_size - (i + 1), &used,
                      plgd_dps_dhcp_set_option_cbk, dhcp_parse_data)) {
      return false;
    }
    i += used + 1;
  }
  return true;
}

static bool
dhcp_set_endpoint(plgd_dps_context_t *ctx, const dhcp_parse_data_t *cbk_data)
{
  assert(ctx);
  assert(cbk_data);
  if (oc_endpoint_addresses_is_selected(
        &ctx->store.endpoints, oc_string_view((const char *)cbk_data->endpoint,
                                              cbk_data->endpoint_size))) {
    DPS_DBG("dps_dhcp_parse_vendor_encapsulated_options: endpoint not changed");
    return false;
  }
  char buffer[MAX_DHCP_VENDOR_ENCAPSULATED_OPTION_BYTE_SIZE + 1];
  size_t len = 0;
  if (cbk_data->endpoint) {
    len = sizeof(buffer) - 1 > cbk_data->endpoint_size ? cbk_data->endpoint_size
                                                       : sizeof(buffer) - 1;
    memcpy(buffer, cbk_data->endpoint, len);
    buffer[len] = '\0';
  } else {
    assert(len == 0);
    buffer[0] = '\0';
  }
  dps_set_endpoint(ctx, buffer, len, /*notify*/ true);
  return true;
}

static bool
dhcp_parse_md_type(const dhcp_parse_data_t *cbk_data,
                   mbedtls_md_type_t *md_type)
{
  assert(cbk_data);
  assert(md_type);
  mbedtls_md_type_t mdt = MBEDTLS_MD_NONE;
  if (cbk_data->certificate_fingerprint_md_type != NULL &&
      cbk_data->certificate_fingerprint_md_type_size > 0) {
    char buffer[MAX_DHCP_VENDOR_ENCAPSULATED_OPTION_BYTE_SIZE + 1];
    size_t len =
      sizeof(buffer) - 1 > cbk_data->certificate_fingerprint_md_type_size
        ? cbk_data->certificate_fingerprint_md_type_size
        : sizeof(buffer) - 1;
    memcpy(buffer, cbk_data->certificate_fingerprint_md_type, len);
    buffer[len] = '\0';
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string(buffer);
    if (md_info == NULL) {
      DPS_ERR("dps_dhcp_parse_vendor_encapsulated_options: unknown fingerprint "
              "md type: %s",
              buffer);
      return false;
    }
    mdt = mbedtls_md_get_type(md_info);
  }
  *md_type = mdt;
  return true;
}

plgd_dps_dhcp_set_values_t
plgd_dps_dhcp_set_values_from_vendor_encapsulated_options(
  plgd_dps_context_t *ctx, const uint8_t *vendor_encapsulated_options,
  size_t vendor_encapsulated_options_size)
{
  assert(ctx);
  assert(vendor_encapsulated_options);
  assert(vendor_encapsulated_options_size > 0);
  dhcp_parse_data_t cbk_data = { 0 };
  cbk_data.dhcp = &ctx->dhcp;
  if (!dps_dhcp_parse_vendor_encapsulated_options(
        &cbk_data, vendor_encapsulated_options,
        vendor_encapsulated_options_size)) {
    return PLGD_DPS_DHCP_SET_VALUES_ERROR;
  }

  mbedtls_md_type_t md_type;
  if (!dhcp_parse_md_type(&cbk_data, &md_type)) {
    return PLGD_DPS_DHCP_SET_VALUES_ERROR;
  }

  if (ctx->certificate_fingerprint.md_type == md_type &&
      oc_endpoint_addresses_is_selected(
        &ctx->store.endpoints, oc_string_view((const char *)cbk_data.endpoint,
                                              cbk_data.endpoint_size)) &&
      dps_is_equal_string_len(ctx->certificate_fingerprint.data,
                              (const char *)cbk_data.certificate_fingerprint,
                              cbk_data.certificate_fingerprint_size)) {
    DPS_DBG("dps_dhcp_parse_vendor_encapsulated_options: endpoint and "
            "certificate_fingerprint are the same");
    return PLGD_DPS_DHCP_SET_VALUES_NOT_CHANGED;
  }
  if (!plgd_dps_set_certificate_fingerprint(
        ctx, md_type, cbk_data.certificate_fingerprint,
        cbk_data.certificate_fingerprint_size)) {
    return PLGD_DPS_DHCP_SET_VALUES_ERROR;
  }
  plgd_dps_dhcp_set_values_t ret = PLGD_DPS_DHCP_SET_VALUES_UPDATED;
  if (dhcp_set_endpoint(ctx, &cbk_data)) {
    ret = PLGD_DPS_DHCP_SET_VALUES_NEED_REPROVISION;
  }
  if (!dps_is_provisioned(ctx)) {
    DPS_DBG(
      "dps_dhcp_parse_vendor_encapsulated_options: not still not provisioned");
    ret = PLGD_DPS_DHCP_SET_VALUES_NEED_REPROVISION;
  }
  return ret;
}

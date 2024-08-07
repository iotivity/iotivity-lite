/******************************************************************
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
 ******************************************************************/

#ifdef OC_SECURITY

#include "api/oc_core_res_internal.h"
#include "api/oc_endpoint_internal.h"
#include "port/oc_clock.h"
#include "port/oc_log_internal.h"
#include "security/oc_pstat_internal.h"
#include "security/oc_tls_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/tls/DTLS.h"
#include "tests/gtest/tls/DTLSClient.h"
#include "util/oc_macros_internal.h"

#include "gtest/gtest.h"

#include <atomic>

// TODO: upgrade mingw, because on v10.2 std::thread doesn't work correctly
#if defined(__MINGW32__) && defined(__GNUC__) && (__GNUC__ < 12)
#define MINGW_WINTHREAD
#include <windows.h>
#else /* __MINGW32__ */
#include <thread>
#endif /* __MINGW32__ */

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_NET_C) && defined(MBEDTLS_TIMING_C)

static constexpr size_t kDeviceID{ 0 };

class TestDTLSWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_TRUE(oc::TestDevice::StartServer());
    oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
    pstat->s = OC_DOS_RFNOP;
  }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }

  void TearDown() override
  {
    oc_tls_close_peers(nullptr, nullptr);
    oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
    pstat->s = OC_DOS_RFNOP;

    oc::TestDevice::Reset();
  }
};

enum class DTLS_STATUS : int {
  DTLS_INIT = 0,
  DTLS_HANDSHAKE_DONE = 1,
  DTLS_ERROR = -1,
};

struct DTLSData
{
  oc::tls::DTLSClient *client;
  const oc_endpoint_t *ep;
  std::atomic<DTLS_STATUS> *status;
};

#ifdef MINGW_WINTHREAD
static DWORD
dtls_thread_win32(void *data)
{
  DTLSData *obj = static_cast<DTLSData *>(data);
  OC_DBG("dtls helper thread started");
  if (!obj->client->ConnectWithHandshake(
        "::1", static_cast<uint16_t>(oc_endpoint_port(obj->ep)))) {
    obj->status->store(DTLS_STATUS::DTLS_ERROR);
    ADD_FAILURE();
    return -1;
  }
  obj->status->store(DTLS_STATUS::DTLS_HANDSHAKE_DONE);
  obj->client->Run();
  return 0;
}
#endif /* MINGW_WINTHREAD */

TEST_F(TestDTLSWithServer, DTLSInactivityMonitor)
{
  oc_clock_time_t timeout_default = oc_dtls_inactivity_timeout();
  oc_dtls_set_inactivity_timeout(OC_CLOCK_SECOND);

  // DTLS endpoint
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID, SECURED, TCP);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  oc::tls::PreSharedKey psk = {
    0xD1, 0xD0, 0xDB, 0x1F, 0x8B, 0xB2, 0x40, 0x55,
    0x9B, 0x07, 0xB8, 0x76, 0x50, 0x7E, 0x25, 0xCF,
  };
  auto hint = oc::tls::AddPresharedKey(kDeviceID, psk);
  ASSERT_TRUE(hint.has_value());

  std::atomic dtls_status{ DTLS_STATUS::DTLS_INIT };
  oc::tls::DTLSClient dtls{};
  dtls.SetPresharedKey(psk, *hint);
  DTLSData data{};
  data.client = &dtls;
  data.ep = &ep;
  data.status = &dtls_status;

#ifdef MINGW_WINTHREAD
  DWORD dtls_thread_id;
  HANDLE dtls_thread =
    CreateThread(nullptr, 0, dtls_thread_win32, &data, 0, &dtls_thread_id);
#else  /* !MINGW_WINTHREAD */
  std::thread dtls_thread{ [&data] {
    OC_DBG("DTLS helper thread started");
    if (!data.client->ConnectWithHandshake(
          "::1", static_cast<uint16_t>(oc_endpoint_port(data.ep)))) {
      data.status->store(DTLS_STATUS::DTLS_ERROR);
      GTEST_FAIL();
    }
    data.status->store(DTLS_STATUS::DTLS_HANDSHAKE_DONE);
    data.client->Run();
  } };
#endif /* MINGW_WINTHREAD */

  while (dtls_status.load() == DTLS_STATUS::DTLS_INIT) {
    oc::TestDevice::PoolEventsMs(50);
  }

  ASSERT_EQ(1, oc_tls_num_peers(kDeviceID));
  uint64_t timeout_msecs =
    (oc_dtls_inactivity_timeout() / OC_CLOCK_SECOND) * 1000;
  oc::TestDevice::PoolEventsMs(timeout_msecs * 2);
  EXPECT_EQ(0, oc_tls_num_peers(kDeviceID));

  dtls.Stop();
#ifdef MINGW_WINTHREAD
  WaitForSingleObject(dtls_thread, INFINITE);
  TerminateThread(dtls_thread, 0);
#else  /* !MINGW_WINTHREAD */
  dtls_thread.join();
#endif /* MINGW_WINTHREAD */

  /* restore defaults */
  oc_dtls_set_inactivity_timeout(timeout_default);
}

#endif /* MBEDTLS_NET_C && MBEDTLS_TIMING_C */

#endif /* OC_SECURITY */

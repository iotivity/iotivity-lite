/******************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef OC_SECURITY

#include <gtest/gtest.h>
#include <pthread.h>

#include "oc_api.h"
#include "oc_cloud_internal.h"

class TestCloudManager : public testing::Test {
public:
  static pthread_mutex_t s_mutex;
  static pthread_cond_t s_cv;
  static oc_handler_t s_handler;
  oc_cloud_context_t m_context;

  static void onPostResponse(oc_client_response_t *) {}

  static int appInit(void)
  {
    int result = oc_init_platform("OCFCloud", nullptr, nullptr);
    result |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                            "ocf.res.1.0.0", nullptr, nullptr);
    return result;
  }

  static void signalEventLoop(void) { pthread_cond_signal(&s_cv); }

  static oc_event_callback_retval_t quitEvent(void *data)
  {
    bool *quit = (bool *)data;
    *quit = true;
    return OC_EVENT_DONE;
  }

  static void poolEvents(uint16_t seconds)
  {
    bool quit = false;
    oc_set_delayed_callback(&quit, quitEvent, seconds);

    while (true) {
      pthread_mutex_lock(&s_mutex);
      oc_clock_time_t next_event = oc_main_poll();
      if (quit) {
        pthread_mutex_unlock(&s_mutex);
        break;
      }
      if (next_event == 0) {
        pthread_cond_wait(&s_cv, &s_mutex);
      } else {
        struct timespec ts;
        ts.tv_sec = (next_event / OC_CLOCK_SECOND);
        ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
        pthread_cond_timedwait(&s_cv, &s_mutex, &ts);
      }
      pthread_mutex_unlock(&s_mutex);
    }
  }

  static void statusHandler(oc_cloud_context_t *, oc_cloud_status_t, void *) {}

protected:
  static void SetUpTestCase()
  {
    s_handler.init = &appInit;
    s_handler.signal_event_loop = &signalEventLoop;
    int ret = oc_main_init(&s_handler);
    ASSERT_EQ(0, ret);
  }

  static void TearDownTestCase() { oc_main_shutdown(); }

  void SetUp() override
  {
    memset(&m_context, 0, sizeof(m_context));
#define UID "501"
    oc_new_string(&m_context.store.uid, UID, strlen(UID));
    m_context.cloud_ep = oc_new_endpoint();
    memset(m_context.cloud_ep, 0, sizeof(oc_endpoint_t));
#define ENDPOINT "coap://224.0.1.187:5683"
    oc_new_string(&m_context.store.ci_server, ENDPOINT, strlen(ENDPOINT));
#define TOKEN "access_token"
    oc_new_string(&m_context.store.access_token, TOKEN, strlen(TOKEN));
#define RTOKEN "refresh_token"
    oc_new_string(&m_context.store.refresh_token, RTOKEN, strlen(RTOKEN));
  }

  void TearDown() override
  {
    oc_free_string(&m_context.store.refresh_token);
    oc_free_string(&m_context.store.access_token);
    oc_free_string(&m_context.store.ci_server);
    oc_free_endpoint(m_context.cloud_ep);
    oc_free_string(&m_context.store.uid);
  }
};

oc_handler_t TestCloudManager::s_handler;
pthread_mutex_t TestCloudManager::s_mutex;
pthread_cond_t TestCloudManager::s_cv;

TEST_F(TestCloudManager, cloud_manager_start_initialized_without_retry_f)
{
  uint8_t retry_original[6] = { 0 };
  size_t retry_original_size = cloud_get_retry(
    retry_original, sizeof(retry_original) / sizeof(retry_original[0]));
  EXPECT_NE((size_t)-1, retry_original_size);
  EXPECT_LT(0, retry_original_size);

  // When
  uint8_t retry[] = { 2 }; // Only a single try
  EXPECT_TRUE(cloud_set_retry(retry, sizeof(retry) / sizeof(retry[0])));
  m_context.store.status = OC_CLOUD_INITIALIZED;
  m_context.store.cps = OC_CPS_READYTOREGISTER;
  cloud_manager_start(&m_context);
  poolEvents(7);
  cloud_manager_stop(&m_context);

  // Then
  EXPECT_LT(0, m_context.retry_count);
  EXPECT_EQ(0, m_context.retry_refresh_token_count);
  EXPECT_EQ(CLOUD_ERROR_CONNECT, m_context.last_error);
  EXPECT_EQ(OC_CLOUD_INITIALIZED, m_context.store.status);

  EXPECT_TRUE(cloud_set_retry(retry_original, retry_original_size));
}

TEST_F(TestCloudManager, cloud_manager_start_initialized_f)
{
  // When
  m_context.store.status = OC_CLOUD_INITIALIZED;
  m_context.store.cps = OC_CPS_READYTOREGISTER;
  cloud_manager_start(&m_context);
  poolEvents(5);
  cloud_manager_stop(&m_context);

  // Then
  EXPECT_LT(0, m_context.retry_count);
  EXPECT_EQ(0, m_context.retry_refresh_token_count);
  EXPECT_EQ(CLOUD_OK, m_context.last_error);
  EXPECT_EQ(OC_CLOUD_INITIALIZED, m_context.store.status);
}

TEST_F(TestCloudManager, cloud_manager_start_registered_f)
{
  // When
  m_context.store.status = OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED;
  m_context.store.expires_in = -1;
  cloud_manager_start(&m_context);
  poolEvents(7);
  cloud_manager_stop(&m_context);

  // Then
  EXPECT_LT(0, m_context.retry_count);
  EXPECT_EQ(0, m_context.retry_refresh_token_count);
  EXPECT_EQ(CLOUD_OK, m_context.last_error);
  EXPECT_EQ(OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED, m_context.store.status);
}

TEST_F(TestCloudManager, cloud_manager_start_with_refresh_token_f)
{
  // When
  m_context.store.status = OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED;
  cloud_manager_start(&m_context);
  poolEvents(7);
  cloud_manager_stop(&m_context);

  // Then
  EXPECT_EQ(0, m_context.retry_count);
  EXPECT_LT(0, m_context.retry_refresh_token_count);
  EXPECT_EQ(CLOUD_OK, m_context.last_error);
  EXPECT_EQ(OC_CLOUD_INITIALIZED | OC_CLOUD_REGISTERED, m_context.store.status);
}

#endif /* !OC_SECURITY */

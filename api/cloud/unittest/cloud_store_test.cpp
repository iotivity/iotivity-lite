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

#include <gtest/gtest.h>

#include "oc_api.h"
#include "oc_cloud_internal.h"
#include "oc_collection.h"

class TestCloudStore : public testing::Test {
public:
  static oc_handler_t s_handler;
  static pthread_mutex_t mutex;
  static pthread_cond_t cv;
  static oc_cloud_context_t s_context;

  static void onPostResponse(oc_client_response_t *data) { (void)data; }

  static int appInit(void)
  {
    int result = oc_init_platform("OCFCloud", NULL, NULL);
    result |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                            "ocf.res.1.0.0", NULL, NULL);
    return result;
  }

  static void signalEventLoop(void)
  {
    pthread_mutex_lock(&mutex);
    pthread_cond_signal(&cv);
    pthread_mutex_unlock(&mutex);
  }

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
      pthread_mutex_lock(&mutex);
      oc_clock_time_t next_event = oc_main_poll();
      if (quit) {
        pthread_mutex_unlock(&mutex);
        break;
      }
      if (next_event == 0) {
        pthread_cond_wait(&cv, &mutex);
      } else {
        struct timespec ts;
        ts.tv_sec = (next_event / OC_CLOCK_SECOND);
        ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
        pthread_cond_timedwait(&cv, &mutex, &ts);
      }
      pthread_mutex_unlock(&mutex);
    }
  }

protected:
  static void SetUpTestCase()
  {
    s_handler.init = &appInit;
    s_handler.signal_event_loop = &signalEventLoop;
    int ret = oc_main_init(&s_handler);
    ASSERT_EQ(0, ret);

    memset(&s_context, 0, sizeof(s_context));
  }

  static void TearDownTestCase() { oc_main_shutdown(); }
};

oc_handler_t TestCloudStore::s_handler;
pthread_mutex_t TestCloudStore::mutex;
pthread_cond_t TestCloudStore::cv;
oc_cloud_context_t TestCloudStore::s_context;

#define ACCESS_TOKEN ("access_token")
#define AUTH_PROVIDER ("auth_provider")
#define CI_SERVER ("ci_server")
#define DEVICE (1234)
#define EXPIRES_IN (5678)
#define REFRESH_TOKEN ("refresh_token")
#define SID ("sid")
#define STATUS (OC_CLOUD_LOGGED_IN)
#define UID ("uid")

TEST_F(TestCloudStore, dump_async)
{
  oc_cloud_store_t store;
  oc_new_string(&store.access_token, ACCESS_TOKEN, strlen(ACCESS_TOKEN));
  oc_new_string(&store.auth_provider, AUTH_PROVIDER, strlen(AUTH_PROVIDER));
  oc_new_string(&store.ci_server, CI_SERVER, strlen(CI_SERVER));
  store.device = DEVICE;
  oc_new_string(&store.refresh_token, REFRESH_TOKEN, strlen(REFRESH_TOKEN));
  oc_new_string(&store.sid, SID, strlen(SID));
  store.status = STATUS;
  oc_new_string(&store.uid, UID, strlen(UID));

  cloud_store_dump_async(&store);
  poolEvents(1);

  oc_cloud_store_t store1;
  memset(&store1, 0, sizeof(store1));
  cloud_store_load(&store1);
#ifdef OC_SECURITY
  EXPECT_STREQ(oc_string(store.access_token), oc_string(store1.access_token));
  EXPECT_STREQ(oc_string(store.auth_provider), oc_string(store1.auth_provider));
  EXPECT_STREQ(oc_string(store.ci_server), oc_string(store1.ci_server));
  EXPECT_EQ(store.device, store1.device);
  EXPECT_STREQ(oc_string(store.refresh_token), oc_string(store1.refresh_token));
  EXPECT_STREQ(oc_string(store.sid), oc_string(store1.sid));
  EXPECT_EQ(store.status, store1.status);
  EXPECT_STREQ(oc_string(store.uid), oc_string(store1.uid));
#else
  EXPECT_STREQ("ocfcloud.com", oc_string(store1.auth_provider));
  EXPECT_STREQ("coap+tcp://devices.ocfcloud.com:5684",
               oc_string(store1.ci_server));
#endif
}

TEST_F(TestCloudStore, load_defaults)
{
  oc_cloud_store_t store1;
  memset(&store1, 0, sizeof(store1));
  cloud_store_load(&store1);

  EXPECT_STREQ("ocfcloud.com", oc_string(store1.auth_provider));
  EXPECT_STREQ("coap+tcp://devices.ocfcloud.com:5684",
               oc_string(store1.ci_server));
}

TEST_F(TestCloudStore, dump)
{
  oc_cloud_store_t store;
  oc_new_string(&store.access_token, ACCESS_TOKEN, strlen(ACCESS_TOKEN));
  oc_new_string(&store.auth_provider, AUTH_PROVIDER, strlen(AUTH_PROVIDER));
  oc_new_string(&store.ci_server, CI_SERVER, strlen(CI_SERVER));
  store.device = DEVICE;
  oc_new_string(&store.refresh_token, REFRESH_TOKEN, strlen(REFRESH_TOKEN));
  oc_new_string(&store.sid, SID, strlen(SID));
  store.status = STATUS;
  oc_new_string(&store.uid, UID, strlen(UID));

  cloud_store_dump(&store);
  oc_cloud_store_t store1;
  memset(&store1, 0, sizeof(store1));
  cloud_store_load(&store1);
#ifdef OC_SECURITY
  EXPECT_STREQ(oc_string(store.access_token), oc_string(store1.access_token));
  EXPECT_STREQ(oc_string(store.auth_provider), oc_string(store1.auth_provider));
  EXPECT_STREQ(oc_string(store.ci_server), oc_string(store1.ci_server));
  EXPECT_EQ(store.device, store1.device);
  EXPECT_STREQ(oc_string(store.refresh_token), oc_string(store1.refresh_token));
  EXPECT_STREQ(oc_string(store.sid), oc_string(store1.sid));
  EXPECT_EQ(store.status, store1.status);
  EXPECT_STREQ(oc_string(store.uid), oc_string(store1.uid));
#else
  EXPECT_STREQ("ocfcloud.com", oc_string(store1.auth_provider));
  EXPECT_STREQ("coap+tcp://devices.ocfcloud.com:5684",
               oc_string(store1.ci_server));
#endif
}

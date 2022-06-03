/******************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
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

class TestCloud : public testing::Test {
public:
  static oc_handler_t s_handler;
  static pthread_mutex_t mutex;
  static pthread_cond_t cv;

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
  }

  static void update_status(oc_cloud_status_t status, void *data)
  {
    oc_cloud_status_t *u_status = (oc_cloud_status_t *)data;
    *u_status = status;
  }

  static void TearDownTestCase() { oc_main_shutdown(); }
};

oc_handler_t TestCloud::s_handler;
pthread_mutex_t TestCloud::mutex;
pthread_cond_t TestCloud::cv;

TEST_F(TestCloud, oc_cloud_get_context)
{
  EXPECT_NE(nullptr, oc_cloud_get_context(0));
  EXPECT_EQ(nullptr, oc_cloud_get_context(1));
}

TEST_F(TestCloud, cloud_status)
{
  oc_cloud_status_t status;
  memset(&status, 0, sizeof(status));
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  ASSERT_NE(nullptr, ctx);
  ctx->store.status = OC_CLOUD_INITIALIZED;
  cloud_manager_cb(ctx);
  EXPECT_EQ(ctx->store.status, status);
}

TEST_F(TestCloud, cloud_set_string)
{
  oc_string_t str;
  memset(&str, 0, sizeof(str));
  cloud_set_string(&str, "a", 1);
  EXPECT_STREQ("a", oc_string(str));

  cloud_set_string(&str, NULL, 1);
  EXPECT_EQ(NULL, oc_string(str));

  cloud_set_string(&str, "b", 0);
  EXPECT_EQ(NULL, oc_string(str));
}

TEST_F(TestCloud, cloud_set_last_error)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  ASSERT_NE(nullptr, ctx);

  int err = 123;

  cloud_set_last_error(ctx, (oc_cloud_error_t)err);
  ASSERT_EQ((oc_cloud_error_t)err, ctx->last_error);
}

TEST_F(TestCloud, cloud_update_by_resource)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  ASSERT_NE(nullptr, ctx);
  ctx->store.status = OC_CLOUD_FAILURE;

  cloud_conf_update_t data;
  data.access_token = (char *)"access_token";
  data.access_token_len = strlen(data.access_token);
  data.auth_provider = (char *)"auth_provider";
  data.auth_provider_len = strlen(data.auth_provider);
  data.ci_server = (char *)"ci_server";
  data.ci_server_len = strlen("ci_server");
  data.sid = (char *)"sid";
  data.sid_len = strlen(data.sid);

  cloud_update_by_resource(ctx, &data);

  EXPECT_STREQ(data.access_token, oc_string(ctx->store.access_token));
  EXPECT_STREQ(data.auth_provider, oc_string(ctx->store.auth_provider));
  EXPECT_STREQ(data.ci_server, oc_string(ctx->store.ci_server));
  EXPECT_STREQ(data.sid, oc_string(ctx->store.sid));
  EXPECT_EQ(OC_CLOUD_INITIALIZED, ctx->store.status);
}

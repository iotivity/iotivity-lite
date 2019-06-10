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

class TestCloudResource : public testing::Test
{
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

oc_handler_t TestCloudResource::s_handler;
pthread_mutex_t TestCloudResource::mutex;
pthread_cond_t TestCloudResource::cv;
oc_cloud_context_t TestCloudResource::s_context;

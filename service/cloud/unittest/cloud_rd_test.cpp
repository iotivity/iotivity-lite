/******************************************************************
 *
 * Copyright 2019 Jozef Kralik  All Rights Reserved.
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

#include "cloud_internal.h"
#include "oc_api.h"
#include "oc_collection.h"

class TestCloudRD : public testing::Test
{
  public:
    static oc_handler_t s_handler;
    static pthread_mutex_t mutex;
    static pthread_cond_t cv;

    static void onPostResponse(oc_client_response_t *data)
    {
        (void)data;
    }

    static int appInit(void)
    {
        int result = oc_init_platform("OCFCloud", NULL, NULL);
        result |= oc_add_device("/oic/d", "oic.d.light", "Lamp",
                                "ocf.1.0.0", "ocf.res.1.0.0", NULL, NULL);
        result |= cloud_init(0, NULL, NULL);
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

        while (true)
        {
            pthread_mutex_lock(&mutex);
            oc_clock_time_t next_event = oc_main_poll();
            if (quit)
            {
                pthread_mutex_unlock(&mutex);
                break;
            }
            if (next_event == 0)
            {
                pthread_cond_wait(&cv, &mutex);
            }
            else
            {
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

    static  oc_resource_t* findResource(oc_link_t* head, oc_resource_t* res) {
        for (oc_link_t* l = head; l; l = l->next ) {
            if (l->resource == res) {
                return l->resource;
            }
        }
        return nullptr;
    }

    static void TearDownTestCase()
    {
        cloud_shutdown(0);
        oc_main_shutdown();
    }
};

oc_handler_t TestCloudRD::s_handler;
pthread_mutex_t TestCloudRD::mutex;
pthread_cond_t TestCloudRD::cv;

TEST_F(TestCloudRD, cloud_publish_f)
{
    // When
    int ret = cloud_rd_publish(NULL);
   
    // Then
    ASSERT_EQ(-1, ret);
}

TEST_F(TestCloudRD, cloud_publish_p)
{
    // When
    oc_resource_t *res1 = oc_new_resource(NULL, "/light/1", 1, 0);
    oc_resource_bind_resource_type(res1, "test");
    int ret = cloud_rd_publish(res1);
   
    // Then
    ASSERT_EQ(0, ret);
    cloud_context_t* ctx = cloud_find_context(0);
    ASSERT_NE(NULL, ctx);
    ASSERT_NE(NULL, ctx->rd_publish_resources);
    EXPECT_EQ(res1, findResource(ctx->rd_publish_resources, res1));
}

TEST_F(TestCloudRD, cloud_delete)
{
    // When
    oc_resource_t *res1 = oc_new_resource(NULL, "/light/1", 1, 0);
    oc_resource_bind_resource_type(res1, "test");
    int ret = cloud_rd_publish(res1);
    ASSERT_EQ(0, ret);
    cloud_rd_delete(res1);
   
    // Then
    cloud_context_t* ctx = cloud_find_context(0);
    ASSERT_NE(NULL, ctx);
    EXPECT_EQ(NULL, findResource(ctx->rd_publish_resources, res1));
}
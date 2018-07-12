/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 *
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

#include <cstdlib>
#include <string>
#include <gtest/gtest.h>

extern "C" {
#include "oc_api.h"
#include "port/oc_clock.h"
}

#define MAX_WAIT_TIME 10
#define RESOURCE_URI "/LightResourceURI"
#define DEVICE_URI "/oic/d"
#define RESOURCE_TYPE "oic.r.light"
#define DEVICE_TYPE "oic.d.light"
#define RESOURCE_INTERFACE "oic.if.baseline"
#define MANUFACTURER_NAME "Samsung"
#define DEVICE_NAME "Table Lamp"
#define OCF_SPEC_VERSION "ocf.1.0.0"
#define OCF_DATA_MODEL_VERSION "ocf.res.1.0.0"

#define RESOURCE_COLLECTION_NAME_ROOM "roomlights"
#define RESOURCE_COLLECTION_TYPE_LIGHT "/lights"
#define RESOURCE_COLLECTION_RELATION "room"

class TestCollectionRequest: public testing::Test
{
    public:
        static oc_handler_t s_handler;
        static oc_resource_t *s_pResource;
        static pthread_mutex_t s_mutex;
        static pthread_cond_t s_cv;
        static oc_endpoint_t *s_pLightEndpoint;
        static oc_resource_t *s_pCol;
        static oc_link_t *s_pLink;

        static int appInit(void)
        {
            PRINT("appInit....\n");
            int result = oc_init_platform(MANUFACTURER_NAME, NULL, NULL);
            result |= oc_add_device(DEVICE_URI, DEVICE_TYPE, DEVICE_NAME,
                                    OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
            return result;
        }

        static void registerResources(void)
        {
            PRINT("registerResources....\n");
            s_pResource = oc_new_resource(NULL, RESOURCE_URI, 1, 0);
            oc_resource_bind_resource_type(s_pResource, RESOURCE_TYPE);
            oc_resource_bind_resource_interface(s_pResource, OC_IF_RW);
            oc_resource_set_default_interface(s_pResource, OC_IF_RW);
            oc_resource_set_discoverable(s_pResource, true);
            oc_resource_set_periodic_observable(s_pResource, 1);
            oc_process_baseline_interface(s_pResource);
            oc_add_resource(s_pResource);
        }

        static void signalEventLoop(void)
        {
            pthread_mutex_lock(&s_mutex);
            pthread_cond_signal(&s_cv);
            pthread_mutex_unlock(&s_mutex);
        }

        static void requestsEntry(void)
        {
            PRINT("requestsEntry....\n");
        }

    protected:
        virtual void SetUp()
        {
        }

        virtual void TearDown()
        {
        }

        static void SetUpTestCase()
        {
            s_handler.init = &appInit;
            s_handler.signal_event_loop = &signalEventLoop;
            s_handler.register_resources = &registerResources;
            s_handler.requests_entry = &requestsEntry;

            oc_set_con_res_announced(false);

            oc_main_init(&s_handler);
        }

        static void TearDownTestCase()
        {
            if (s_pResource)
            {
                oc_delete_resource(s_pResource);
            }

            oc_main_shutdown();
        }
};


oc_resource_t *TestCollectionRequest::s_pResource = nullptr;
oc_handler_t TestCollectionRequest::s_handler;
pthread_mutex_t TestCollectionRequest::s_mutex;
pthread_cond_t TestCollectionRequest::s_cv;
oc_resource_t *TestCollectionRequest::s_pCol = nullptr;
oc_link_t *TestCollectionRequest::s_pLink = nullptr;

TEST_F(TestCollectionRequest, AddCollectionTest_P)
{
    s_pCol = oc_new_collection(RESOURCE_COLLECTION_NAME_ROOM,
                               RESOURCE_COLLECTION_TYPE_LIGHT, 1, 0);
    EXPECT_TRUE(TestCollectionRequest::s_pCol != NULL) << "Failed to make new collection";
}

TEST_F(TestCollectionRequest, DeleteCollectionTest_P)
{
    oc_delete_collection(TestCollectionRequest::s_pCol);
}

TEST_F(TestCollectionRequest, AddLinkTest_P)
{

    s_pLink = oc_new_link(s_pResource);
    EXPECT_TRUE(s_pLink != NULL) << "Failed to make new link";
}

TEST_F(TestCollectionRequest, DeleteLinkTest_P)
{
    oc_delete_link(s_pLink);
}

TEST_F(TestCollectionRequest, AddLinkRelationTest_P)
{
    s_pLink = oc_new_link(s_pResource);
    oc_link_add_rel(s_pLink, RESOURCE_COLLECTION_RELATION);
}

TEST_F(TestCollectionRequest, SetLinkInstanceTest_P)
{
    oc_link_set_ins(s_pLink, RESOURCE_COLLECTION_RELATION);
}

TEST_F(TestCollectionRequest, AddCollectionLinkTest_P)
{
    s_pCol = oc_new_collection(RESOURCE_COLLECTION_NAME_ROOM,
                               RESOURCE_COLLECTION_TYPE_LIGHT, 1, 0);
    oc_resource_set_discoverable(s_pCol, true);
    s_pLink = oc_new_link(s_pResource);
    oc_collection_add_link(s_pCol, s_pLink);
}

TEST_F(TestCollectionRequest, RemoveCollectionLinkTest_P)
{
    oc_collection_remove_link(s_pCol, s_pLink);
    oc_delete_link(s_pLink);
    oc_delete_collection(TestCollectionRequest::s_pCol);
}

TEST_F(TestCollectionRequest, GetCollectionFromLinkTest_P)
{
    s_pCol = oc_new_collection(RESOURCE_COLLECTION_NAME_ROOM,
                               RESOURCE_COLLECTION_TYPE_LIGHT, 1, 0);
    s_pLink = oc_new_link(s_pResource);
    oc_collection_add_link(s_pCol, s_pLink);
    oc_link_t *link =  oc_collection_get_links(s_pCol);
    EXPECT_TRUE(link != NULL) << "Failed to get collection links ";
}



/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include <gtest/gtest.h>

#include "st_queue.h"

static st_queue_t *queue = NULL;

typedef struct test_queue_item {
    struct test_queue_item *next;
    int num;
} test_queue_item_t;

class TestSTQueue: public testing::Test
{
    protected:
        virtual void SetUp()
        {
          queue = st_queue_initialize();
        }

        virtual void TearDown()
        {
          st_queue_deinitialize(queue);
          queue = NULL;
        }
};

TEST(TestSTQueue_init, st_queue_initialize_P)
{
    st_queue_t *q = st_queue_initialize();
    EXPECT_NE(NULL, q);
    st_queue_deinitialize(q);
}

TEST_F(TestSTQueue, st_queue_push_P)
{
    test_queue_item_t *item =
        (test_queue_item_t *)malloc(sizeof(test_queue_item_t));
    item->num = 1;
    int ret = st_queue_push(queue, item);
    EXPECT_EQ(0, ret);
    item = (test_queue_item_t *)st_queue_pop(queue);
    free(item);
}

TEST_F(TestSTQueue, st_queue_push_N)
{
    int ret = st_queue_push(NULL, NULL);
    EXPECT_NE(0, ret);
}

TEST_F(TestSTQueue, st_queue_pop_P)
{
    test_queue_item_t *item =
        (test_queue_item_t *)malloc(sizeof(test_queue_item_t));
    item->num = 1;
    int ret = st_queue_push(queue, item);
    EXPECT_EQ(0, ret);

    item = (test_queue_item_t *)st_queue_pop(queue);
    EXPECT_EQ(1, item->num);
    free(item);
}

TEST_F(TestSTQueue, st_queue_pop_N)
{
    test_queue_item_t *item =
        (test_queue_item_t *)st_queue_pop(NULL);
    EXPECT_EQ(NULL, item);
}

TEST_F(TestSTQueue, st_queue_get_head_P)
{
    test_queue_item_t *item =
        (test_queue_item_t *)malloc(sizeof(test_queue_item_t));
    item->num = 1;
    int ret = st_queue_push(queue, item);
    EXPECT_EQ(0, ret);

    test_queue_item_t *head =
        (test_queue_item_t *)st_queue_get_head(queue);
    EXPECT_EQ(item, head);

    item = (test_queue_item_t *)st_queue_pop(queue);
    free(item);
}
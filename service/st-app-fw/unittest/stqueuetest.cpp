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

void *test_queue_add_handler(void *value)
{
    test_queue_item_t *item = (test_queue_item_t *)malloc(sizeof(test_queue_item_t));
    item->num = *(int *)value;
    return item;
}

void test_queue_free_handler(void *item)
{
    free(item);
}

class TestSTQueue: public testing::Test
{
    protected:
        virtual void SetUp()
        {
          queue = st_queue_initialize(test_queue_add_handler,
                                      test_queue_free_handler);
        }

        virtual void TearDown()
        {
          st_queue_deinitialize(queue);
          queue = NULL;
        }
};

TEST(TestSTQueue_init, st_queue_initialize_P)
{
    st_queue_t *q = st_queue_initialize(test_queue_add_handler,
                                        test_queue_free_handler);
    EXPECT_NE(NULL, q);
    st_queue_deinitialize(q);
}

TEST_F(TestSTQueue, st_queue_push_P)
{
    int num = 1;
    int ret = st_queue_push(queue, &num);
    EXPECT_EQ(0, ret);
}

TEST_F(TestSTQueue, st_queue_push_N)
{
    int ret = st_queue_push(NULL, NULL);
    EXPECT_NE(0, ret);
}

TEST_F(TestSTQueue, st_queue_pop_P)
{
    int num = 1;
    int ret = st_queue_push(queue, &num);
    EXPECT_EQ(0, ret);

    test_queue_item_t *item = (test_queue_item_t *)st_queue_pop(queue);
    EXPECT_EQ(1, item->num);
    st_queue_free_item(queue, item);
}

TEST_F(TestSTQueue, st_queue_pop_N)
{
    test_queue_item_t *item =
        (test_queue_item_t *)st_queue_pop(NULL);
    EXPECT_EQ(NULL, item);
}

TEST_F(TestSTQueue, st_queue_get_head_P)
{
    int num = 1;
    int ret = st_queue_push(queue, &num);
    EXPECT_EQ(0, ret);

    test_queue_item_t *head =
        (test_queue_item_t *)st_queue_get_head(queue);
    EXPECT_NE(NULL, head);
}

TEST_F(TestSTQueue, st_queue_free_all_items)
{
    int num[3] = {1, 2, 3};
    int i;
    for (i = 0; i < 3; i++)
        st_queue_push(queue, &num[i]);
    
    st_queue_free_all_items(queue);

    test_queue_item_t *head =
        (test_queue_item_t *)st_queue_get_head(queue);
    EXPECT_EQ(NULL, head);
}
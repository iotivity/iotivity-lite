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


#include <stdlib.h>
#include "gtest/gtest.h"

#include "oc_rep.h"

TEST(TestRep, OCRepFinalizeTest_P)
{
    int repSize = oc_rep_finalize();
    EXPECT_NE(repSize, -1);
}

/*
 * Most code done here is to enable testing without passing the code through the
 * framework. End users are not expected to call oc_rep_new, oc_rep_set_pool
 * and oc_parse_rep
 */
TEST(TestRep, OCRepSetGetInt)
{

    /*
     * intilize everything needed to call 'oc_parse_rep
     * calling oc_rep_new and getting the payload pointer must be done before
     * calling oc_rep_start_root_object.
     */
    uint8_t buf[1024];
    oc_rep_new(&buf[0], 1024);
    uint8_t *payload = g_encoder.data.ptr;
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0 ,0 };
    oc_rep_set_pool(&rep_objects);

    /* add int value "ultimate_answer":42 to root object */
    oc_rep_start_root_object();
    oc_rep_set_int(root, ultimate_answer, 42);
    oc_rep_end_root_object();

    /* convert CborEncoder to oc_rep_t */
    int payload_len = oc_rep_finalize();
    EXPECT_NE(payload_len, -1);
    oc_rep_t *rep = NULL;
    oc_parse_rep(payload, payload_len, &rep);
    ASSERT_TRUE(rep != NULL);

    /* read the ultimate_answer from  the oc_rep_t */
    int ultimate_answer_out = 0;
    oc_rep_get_int(rep, "ultimate_answer", &ultimate_answer_out);
    EXPECT_EQ(42, ultimate_answer_out);
    oc_free_rep(rep);
}

TEST(TestRep, OCRepSetGetTextString)
{

    /*
     * intilize everything needed to call 'oc_parse_rep
     * calling oc_rep_new and getting the payload pointer must be done before
     * calling oc_rep_start_root_object.
     */
    uint8_t buf[1024];
    oc_rep_new(&buf[0], 1024);
    uint8_t *payload = g_encoder.data.ptr;
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0 ,0 };
    oc_rep_set_pool(&rep_objects);

    /* add text string value "hal9000":"Dave" to root object */
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, hal9000, "Dave");
    oc_rep_end_root_object();

    /* convert CborEncoder to oc_rep_t */
    int payload_len = oc_rep_finalize();
    EXPECT_NE(payload_len, -1);
    oc_rep_t *rep = NULL;
    oc_parse_rep(payload, payload_len, &rep);
    ASSERT_TRUE(rep != NULL);

    /* read the hal9000 from  the oc_rep_t */
    char* hal9000_out = 0;
    size_t str_len;
    oc_rep_get_string(rep, "hal9000", &hal9000_out, &str_len);
    EXPECT_STREQ("Dave", hal9000_out);
    EXPECT_EQ(4, str_len);
    oc_free_rep(rep);
}

TEST(TestRep, OCRepSetGetIntArray)
{

    /*
     * intilize everything needed to call 'oc_parse_rep
     * calling oc_rep_new and getting the payload pointer must be done before
     * calling oc_rep_start_root_object.
     */
    uint8_t buf[1024];
    oc_rep_new(&buf[0], 1024);
    uint8_t *payload = g_encoder.data.ptr;
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0 ,0 };
    oc_rep_set_pool(&rep_objects);

    /* add int array to root object */
    int fib[] = {1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89 };
    oc_rep_start_root_object();
    oc_rep_set_int_array(root, fibonacci, fib, (int)(sizeof(fib)/ sizeof(fib[0]) ) );
    oc_rep_end_root_object();

    /* convert CborEncoder to oc_rep_t */
    int payload_len = oc_rep_finalize();
    EXPECT_NE(payload_len, -1);
    oc_rep_t *rep = NULL;
    oc_parse_rep(payload, payload_len, &rep);
    ASSERT_TRUE(rep != NULL);

    /* read the 'fibonacci' array from  the oc_rep_t */
    int* fib_out = 0;
    size_t fib_len;
    oc_rep_get_int_array(rep, "fibonacci", &fib_out, &fib_len);
    ASSERT_EQ(sizeof(fib)/sizeof(fib[0]), fib_len);
    for (size_t i = 0; i < fib_len; ++i ) {
      EXPECT_EQ(fib[i], fib_out[i]);
    }
    oc_free_rep(rep);
}

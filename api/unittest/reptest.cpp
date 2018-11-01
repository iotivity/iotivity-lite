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

TEST(TestRep, OCRepSetGetInt)
{
    uint8_t buf[1024];
    oc_rep_new(&buf[0], 1024);

    /* add int value "ultimate_answer":42 to root object */
    oc_rep_start_root_object();
    oc_rep_set_int(root, ultimate_answer, 42);
    oc_rep_end_root_object();

    /* convert CborEncoder to oc_rep_t */
    uint8_t *payload = g_encoder.data.ptr;
    int payload_len = oc_rep_finalize();
    EXPECT_NE(payload_len, -1);
    oc_rep_t *rep = NULL;
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0 ,0 };
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(payload, payload_len, &rep);
    ASSERT_TRUE(rep != NULL);

    /* read the ultimate_answer from  the oc_rep_t */
    int ultimate_answer_out = 0;
    oc_rep_get_int(rep, "ultimate_answer", &ultimate_answer_out);
    EXPECT_EQ(42, ultimate_answer_out);
    oc_free_rep(rep);
}

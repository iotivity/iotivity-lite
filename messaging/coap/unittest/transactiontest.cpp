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
#include "gtest/gtest.h"

extern "C" {
#include "transactions.h"
#include "oc_api.h"
#include "oc_endpoint.h"
#include "oc_signal_event_loop.h"
#define delete pseudo_delete
#include "oc_core_res.h"
#undef delete
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


class TestCoapTransaction: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            oc_ri_init();
            oc_core_init();
            oc_init_platform(MANUFACTURER_NAME, NULL, NULL);
            oc_add_device(DEVICE_URI, DEVICE_TYPE, DEVICE_NAME,
                          OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
        }

        virtual void TearDown()
        {
            coap_free_all_transactions();
            oc_ri_shutdown();
            oc_connectivity_shutdown(0);
            oc_core_shutdown();
        }
};

/*
 * @API: coap_new_transaction()
 * @Description: Tries to create new transaction
 * @PassCondition: Should create new transaction
 * @PreCondition: Create new endpoint and get mid
 * @PostCondition: N/A
 */
TEST_F(TestCoapTransaction, CreateTransactionTest_P)
{
    oc_endpoint_t *endpoint = oc_new_endpoint();
    uint16_t mid = coap_get_mid();;
    coap_transaction_t *transaction = NULL;
    transaction = coap_new_transaction(mid, endpoint);
    EXPECT_TRUE(NULL != transaction) << "Failed to create transaction";
}

/*
 * @API: coap_get_transaction_by_mid()
 * @Description: Tries to get transaction by mid
 * @PassCondition: Should get transaction by mid
 * @PreCondition: Creat new endpoint, Get mid and Create new transaction
 * @PostCondition: N/A
 */
TEST_F(TestCoapTransaction, GetTransactionTest_P)
{

    oc_endpoint_t *endpoint = oc_new_endpoint();
    uint16_t mid = coap_get_mid();;
    coap_transaction_t *transaction = coap_new_transaction(mid, endpoint);
    coap_transaction_t *retrievedTransaction = coap_get_transaction_by_mid(mid);
    EXPECT_EQ(retrievedTransaction, transaction) << "Failed to get transaction";
}

/*
 * @API: coap_check_transactions()
 * @Description: Tries to check all transactions
 * @PassCondition: Should check all transactions
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapTransaction, CheckTransactionTest_P)
{

    coap_check_transactions();
}

/*
 * @API: coap_free_all_transactions()
 * @Description: Tries to free all transactions
 * @PassCondition: Should free all transactions
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapTransaction, FreeAllTransactionTest_P)
{

    coap_free_all_transactions();
}

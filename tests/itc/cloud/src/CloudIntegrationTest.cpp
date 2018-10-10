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

#include "cloud_access.h"
#include <gtest/gtest.h>
#include "CloudHelper.h"

class CloudIntegrationTest: public ::testing::Test {
public:

	virtual void SetUp() {
	}

	virtual void TearDown() {
	}
};

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignUp with auth API with positive values
 * @target oc_sign_up_with_auth(oc_endpoint_t *endpoint, const char *auth_provider,
 const char *auth_code, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @test_data     1.resource data
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * @procedure     1. call signup with auth function
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected Resource api should return true
 */
TEST(CloudIntegrationTest, cloud_signup_with_auth_P)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_TRUE(m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE));

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignUp with auth API callback return
 * @target oc_sign_up_with_auth(oc_endpoint_t *endpoint, const char *auth_provider,
 const char *auth_code, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @test_data     1. resource data, authcode, address, provider
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * @procedure     1. call signup with auth function
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected Resource callback should be called
 */
TEST(CloudIntegrationTest, cloud_signup_with_auth_clientCB_P)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_TRUE(m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE));

	m_pCloudHelper->waitForEvent();
	EXPECT_TRUE(m_pCloudHelper->s_isRequestSucessfull);

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignUp with auth API with address null value
 * @target oc_sign_up_with_auth(oc_endpoint_t *endpoint, const char *auth_provider,
 const char *auth_code, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @test_data     1. resource authcode, address, provider
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * @procedure     1. call signup with auth function with NULL address value
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected Resource api should return false
 */
TEST(CloudIntegrationTest, cloud_signup_with_auth_address_null_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_FALSE(m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER,NULL,AUTH_CODE));

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignUp with auth API with auth null value
 * @target oc_sign_up_with_auth(oc_endpoint_t *endpoint, const char *auth_provider,
 const char *auth_code, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @test_data     1. resource data,authcode, address, provider
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * @procedure     1. call signup with auth function with NULL address value
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected Resource api should return false
 */
TEST(CloudIntegrationTest, cloud_signup_with_auth_null_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_FALSE(m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER,ADDRESS,NULL));

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignUp with auth API with null value
 * @target oc_sign_up_with_auth(oc_endpoint_t *endpoint, const char *auth_provider,
 const char *auth_code, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @test_data     1. resource data
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * @procedure     1. call signup with auth function with NULL value
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected Resource api should return false
 */
TEST(CloudIntegrationTest, cloud_signup_with_param_null_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_FALSE(m_pCloudHelper->ocSignUpWithAuth(NULL, NULL, NULL));

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();
}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignIn API with positive values
 * @target oc_sign_in(oc_endpoint_t *endpoint, const char *uid,
 const char *access_token, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * 3. SignUp
 * @procedure     1. call signIn
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected api should return true value
 */
TEST(CloudIntegrationTest, cloud_signin_return_check_P)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_TRUE(m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE));

	m_pCloudHelper->waitForEvent();

	EXPECT_TRUE(m_pCloudHelper->ocSignInWithAuth());
	m_pCloudHelper->waitForEvent();

	m_pCloudHelper->ocSignOutWithAuth();

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignIn API with positive values
 * @target oc_sign_in(oc_endpoint_t *endpoint, const char *uid,
 const char *access_token, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * 3. SignUp
 * @procedure     1. call signIn
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected api should return true value
 */
TEST(CloudIntegrationTest, cloud_signin_cb_check_P)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_TRUE(m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE));
	m_pCloudHelper->waitForEvent();

	EXPECT_TRUE(m_pCloudHelper->ocSignInWithAuth());
	m_pCloudHelper->waitForEvent();
	EXPECT_TRUE(m_pCloudHelper->s_isRequestSucessfull);

	m_pCloudHelper->ocSignOutWithAuth();

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud Signout API with negative values
 * @target oc_sign_in(oc_endpoint_t *endpoint, const char *uid,
 const char *access_token, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * 3. SignUp
 * @procedure     1. call signIn with emty string
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected api should return false value
 */
TEST(CloudIntegrationTest, cloud_signin_empty_value_check_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE);

	m_pCloudHelper->waitForEvent();

	EXPECT_FALSE(m_pCloudHelper->ocSignInWithAuth(false, "","", false));
	m_pCloudHelper->waitForEvent();

	m_pCloudHelper->ocSignOutWithAuth();

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud Signout API with negative values
 * @target oc_sign_in(oc_endpoint_t *endpoint, const char *uid,
 const char *access_token, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * 3. SignUp
 * @procedure     1. call signIn with invalid string
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected api should return false value
 */
TEST(CloudIntegrationTest, cloud_signin_invalid_value_check_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_TRUE(m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE));

	m_pCloudHelper->waitForEvent();

	EXPECT_FALSE(m_pCloudHelper->ocSignInWithAuth(false, "asdf","asdf123", false));
	m_pCloudHelper->waitForEvent();

	m_pCloudHelper->ocSignOutWithAuth();

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud Signout API with negative values
 * @target oc_sign_in(oc_endpoint_t *endpoint, const char *uid,
 const char *access_token, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * 3. SignUp
 * @procedure     1. call signIn with enpoint null value
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected api should return false value
 */
TEST(CloudIntegrationTest, cloud_signin_endpoint_null_check_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_TRUE(m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE));

	m_pCloudHelper->waitForEvent();

	EXPECT_FALSE(m_pCloudHelper->ocSignInWithAuth(true, NULL, NULL, false));
	m_pCloudHelper->waitForEvent();

	m_pCloudHelper->ocSignOutWithAuth();

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud Signout API with negative values
 * @target oc_sign_in(oc_endpoint_t *endpoint, const char *uid,
 const char *access_token, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * 3. SignUp
 * @procedure     1. call signIn with callback null value
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected api should return false value
 */
TEST(CloudIntegrationTest, cloud_signin_callback_null_check_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_TRUE(m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE));

	m_pCloudHelper->waitForEvent();

	EXPECT_FALSE(m_pCloudHelper->ocSignInWithAuth(false, NULL, NULL, true));
	m_pCloudHelper->waitForEvent();

	m_pCloudHelper->ocSignOutWithAuth();

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignOut API with positive values
 * @target oc_sign_out(oc_endpoint_t *endpoint, const char *access_token,
 size_t device_index, oc_response_handler_t handler,
 void *user_data);
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * 3. SignUp
 * 4. SingIn
 * @procedure     1. call signout
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected api should return true value
 */
TEST(CloudIntegrationTest, cloud_signout_return_check_P)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE);
	m_pCloudHelper->waitForEvent();
	m_pCloudHelper->ocSignInWithAuth();
	m_pCloudHelper->waitForEvent();

	EXPECT_TRUE(m_pCloudHelper->ocSignOutWithAuth());

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignOut API with positive values for callback check
 * @target oc_sign_out(oc_endpoint_t *endpoint, const char *access_token,
 size_t device_index, oc_response_handler_t handler,
 void *user_data);
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * 3. SignUp
 * 4. SingIn
 * @procedure     1. call signout
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected api registerd callback should be called
 */
TEST(CloudIntegrationTest, cloud_signout_cb_check_P)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE);
	m_pCloudHelper->waitForEvent();
	m_pCloudHelper->ocSignInWithAuth();
	m_pCloudHelper->waitForEvent();

	m_pCloudHelper->ocSignOutWithAuth();
	m_pCloudHelper->waitForEvent();

	EXPECT_TRUE(m_pCloudHelper->s_isRequestSucessfull);

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignOut API with Negative values
 * @target oc_sign_out(oc_endpoint_t *endpoint, const char *access_token,
 size_t device_index, oc_response_handler_t handler,
 void *user_data);
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * 3. SignUp
 * 4. SingIn
 * @procedure     1. call signout with null access token
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected api should return false
 */
TEST(CloudIntegrationTest, cloud_signout_access_null_check_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE);
	m_pCloudHelper->waitForEvent();
	m_pCloudHelper->ocSignInWithAuth();
	m_pCloudHelper->waitForEvent();

	EXPECT_FALSE(m_pCloudHelper->ocSignOutWithAuth(false, NULL, false));

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignOut API with Negative values
 * @target oc_sign_out(oc_endpoint_t *endpoint, const char *access_token,
 size_t device_index, oc_response_handler_t handler,
 void *user_data);
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * 3. SignUp
 * 4. SingIn
 * @procedure     1. call signout with empty access token
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected api should return false
 */
TEST(CloudIntegrationTest, cloud_signout_access_empty_check_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE);
	m_pCloudHelper->waitForEvent();
	m_pCloudHelper->ocSignInWithAuth();
	m_pCloudHelper->waitForEvent();

	EXPECT_FALSE(m_pCloudHelper->ocSignOutWithAuth(false, "", false));

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignOut API with Negative values
 * @target oc_sign_out(oc_endpoint_t *endpoint, const char *access_token,
 size_t device_index, oc_response_handler_t handler,
 void *user_data);
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * 3. SignUp
 * 4. SingIn
 * @procedure     1. call signout with invalid access token
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected api should return false
 */
TEST(CloudIntegrationTest, cloud_signout_access_invalid_check_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE);
	m_pCloudHelper->waitForEvent();
	m_pCloudHelper->ocSignInWithAuth();
	m_pCloudHelper->waitForEvent();

	EXPECT_FALSE(m_pCloudHelper->ocSignOutWithAuth(false, "45ae0de2e6eed78f2734", false));

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignOut API with Negative values
 * @target oc_sign_out(oc_endpoint_t *endpoint, const char *access_token,
 size_t device_index, oc_response_handler_t handler,
 void *user_data);
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * 3. SignUp
 * 4. SingIn
 * @procedure     1. call signout with null endpoint
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected api should return false
 */
TEST(CloudIntegrationTest, cloud_signout_endpoint_null_check_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE);
	m_pCloudHelper->waitForEvent();
	m_pCloudHelper->ocSignInWithAuth();
	m_pCloudHelper->waitForEvent();

	EXPECT_FALSE(m_pCloudHelper->ocSignOutWithAuth(true, NULL, false));

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignOut API with Negative values
 * @target oc_sign_out(oc_endpoint_t *endpoint, const char *access_token,
 size_t device_index, oc_response_handler_t handler,
 void *user_data);
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * 3. SignUp
 * 4. SingIn
 * @procedure     1. call signout with null callback value
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected api should return false
 */
TEST(CloudIntegrationTest, cloud_signout_callback_null_check_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	m_pCloudHelper->ocSignUpWithAuth(AUTH_CODE_PROVIDER, ADDRESS,AUTH_CODE);
	m_pCloudHelper->waitForEvent();
	m_pCloudHelper->ocSignInWithAuth();
	m_pCloudHelper->waitForEvent();

	EXPECT_FALSE(m_pCloudHelper->ocSignOutWithAuth(false, NULL, true));

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignUp API with positive values
 * @target oc_sign_up(oc_endpoint_t *endpoint, const char *auth_provider,
 const char *uid, const char *access_token, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @test_data     1.resource data, authprovider, accesstoken, uid
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * @procedure     1. call signup with auth function
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected Resource api should return true
 */
TEST(CloudIntegrationTest, cloud_signup_check_P)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_TRUE(m_pCloudHelper->ocSignUp());

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignUp API callback return
 * @target oc_sign_up(oc_endpoint_t *endpoint, const char *auth_provider,
 const char *uid, const char *access_token, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @test_data     1.resource data, authprovider, accesstoken, uid
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * @procedure     1. call signup with auth function
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected Resource callback should be called
 */
TEST(CloudIntegrationTest, cloud_signup_clientCB_P)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_TRUE(m_pCloudHelper->ocSignUp());

	m_pCloudHelper->waitForEvent();
	EXPECT_TRUE(m_pCloudHelper->s_isRequestSucessfull);

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignUp with endpoint null value
 * @target oc_sign_up(oc_endpoint_t *endpoint, const char *auth_provider,
 const char *uid, const char *access_token, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @test_data     1.resource data, authprovider, accesstoken, uid
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * @procedure     1. call signup function with NULL endpoint value
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected Resource api should return false
 */
TEST(CloudIntegrationTest, cloud_signup_null_endpoint_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_FALSE(m_pCloudHelper->ocSignUp(true, NULL, NULL,NULL, false));

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignUp with param null value
 * @target oc_sign_up(oc_endpoint_t *endpoint, const char *auth_provider,
 const char *uid, const char *access_token, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @test_data     1.resource data, authprovider, accesstoken, uid
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * @procedure     1. call signup function with NULL value
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected Resource api should return false
 */
TEST(CloudIntegrationTest, cloud_signup_null_value_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_FALSE(m_pCloudHelper->ocSignUp(false, NULL, NULL,NULL, false));

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignUp with param empty string value
 * @target oc_sign_up(oc_endpoint_t *endpoint, const char *auth_provider,
 const char *uid, const char *access_token, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @test_data     1.resource data, authprovider, accesstoken, uid
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * @procedure     1. call signup function with empty string value
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected Resource api should return false
 */
TEST(CloudIntegrationTest, cloud_signup_empty_string_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_FALSE(m_pCloudHelper->ocSignUp(false, "", "", "", false));

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignUp with param Invalid string value
 * @target oc_sign_up(oc_endpoint_t *endpoint, const char *auth_provider,
 const char *uid, const char *access_token, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @test_data     1.resource data, authprovider, accesstoken, uid
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * @procedure     1. call signup function with Invalid string value
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected Resource api should return false
 */
TEST(CloudIntegrationTest, cloud_signup_invalid_string_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_FALSE(m_pCloudHelper->ocSignUp(false, "123465789", "asdf123456789", "fdsa123456789", false));

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}

/**
 * @since 2018-05-25
 * @see none
 * @objective Test iotivity-constrained cloud SignUp with callback null value
 * @target oc_sign_up(oc_endpoint_t *endpoint, const char *auth_provider,
 const char *uid, const char *access_token, size_t device_index,
 oc_response_handler_t handler, void *user_data);
 * @test_data     1.resource data, authprovider, accesstoken, uid
 * @pre_condition 1. create resource
 * 2. start oc_main_init
 * @procedure     1. call signup function with callback null value
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown
 * @expected Resource api should return false
 */
TEST(CloudIntegrationTest, cloud_signup_callback_null_N)
{

	CloudHelper *m_pCloudHelper;
	m_pCloudHelper = CloudHelper::getInstance();
	m_pCloudHelper->createResource();

	EXPECT_FALSE(m_pCloudHelper->ocSignUp(false, NULL, NULL, NULL, true));

	m_pCloudHelper->unRegisterResources();
	m_pCloudHelper->shutDown();

}


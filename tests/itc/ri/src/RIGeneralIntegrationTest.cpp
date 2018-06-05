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

#include "RIHelper.h"

#include <gtest/gtest.h>

class RIGeneralIntegrationTest: public ::testing::Test {
public:

	virtual void SetUp() {
	}

	virtual void TearDown() {
	}
};

TEST(RIGeneralIntegrationTest, ri_nonsecure_initserver_P)
{

	RIHelper *m_pRIHelper;
	m_pRIHelper = RIHelper::getInstance();
	m_pRIHelper->initServer();
	m_pRIHelper->shutDown();
}

TEST(RIGeneralIntegrationTest, ri_nonsecure_initclient_P)
{

	RIHelper *m_pRIHelper;
	m_pRIHelper = RIHelper::getInstance();
	m_pRIHelper->initClient();
	m_pRIHelper->shutDown();
}

TEST(RIGeneralIntegrationTest, ri_nonsecure_client_createResource_P)
{

	RIHelper *m_pRIHelper;
	m_pRIHelper = RIHelper::getInstance();

	m_pRIHelper->createResource();
	m_pRIHelper->discoverResource();
	m_pRIHelper->waitForEvent();
	EXPECT_TRUE( m_pRIHelper->s_isDiscoverResourceSucessfull );
	m_pRIHelper->unRegisterResources();
	m_pRIHelper->shutDown();
}

TEST(RIGeneralIntegrationTest, ri_nonsecure_client_discover_P)
{

	RIHelper *m_pRIHelper;
	m_pRIHelper = RIHelper::getInstance();

	m_pRIHelper->createResource();
	m_pRIHelper->discoverResource();
	m_pRIHelper->waitForEvent();
	EXPECT_TRUE( m_pRIHelper->s_isDiscoverResourceSucessfull );
	m_pRIHelper->unRegisterResources();
	m_pRIHelper->shutDown();
}

TEST(RIGeneralIntegrationTest, ri_nonsecure_clien_observe_P)
{

	RIHelper *m_pRIHelper;
	m_pRIHelper = RIHelper::getInstance();

	m_pRIHelper->createResource();
	m_pRIHelper->discoverResource();
	m_pRIHelper->waitForEvent();
	m_pRIHelper->observeResource();
	m_pRIHelper->waitForEvent();
	EXPECT_TRUE( m_pRIHelper->s_isObserveResourceSuccessfull);
	m_pRIHelper->unRegisterResources();
	m_pRIHelper->shutDown();
}

TEST(RIGeneralIntegrationTest, ri_nonsecure_clien_post_request_P)
{

	RIHelper *m_pRIHelper;
	m_pRIHelper = RIHelper::getInstance();

	m_pRIHelper->createResource();
	m_pRIHelper->discoverResource();
	m_pRIHelper->waitForEvent();
	m_pRIHelper->postRequestResource();
	m_pRIHelper->waitForEvent();
	EXPECT_TRUE( m_pRIHelper->s_isRequestSucessfull);
	m_pRIHelper->unRegisterResources();
	m_pRIHelper->shutDown();
}

TEST(RIGeneralIntegrationTest, ri_nonsecure_clien_put_request_P)
{

	RIHelper *m_pRIHelper;
	m_pRIHelper = RIHelper::getInstance();

	m_pRIHelper->createResource();
	m_pRIHelper->discoverResource();
	m_pRIHelper->waitForEvent();
	m_pRIHelper->putRequestResource();
	m_pRIHelper->waitForEvent();
	EXPECT_TRUE( m_pRIHelper->s_isRequestSucessfull);
	m_pRIHelper->unRegisterResources();
	m_pRIHelper->shutDown();
}

TEST(RIGeneralIntegrationTest, ri_nonsecure_clien_get_request_P)
{

	RIHelper *m_pRIHelper;
	m_pRIHelper = RIHelper::getInstance();

	m_pRIHelper->createResource();
	m_pRIHelper->discoverResource();
	m_pRIHelper->waitForEvent();
	m_pRIHelper->getResource();
	m_pRIHelper->waitForEvent();
	EXPECT_TRUE( m_pRIHelper->s_isRequestSucessfull);
	m_pRIHelper->unRegisterResources();
	m_pRIHelper->shutDown();
}


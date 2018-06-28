#include <gtest/gtest.h>
#include <cstdlib>

extern "C"{
    #include "st_data_manager.h"
    #include "st_resource_manager.h"
    #include "oc_api.h"
    #include "oc_ri.h"
    #include "st_port.h"
}

static int device_index = 0;
static bool
resource_handler(oc_request_t *request)
{
    (void)request;
    return true;
}

class TestSTResourceManager: public testing::Test
{
    protected:
        virtual void SetUp()
        {

        }

        virtual void TearDown()
        {

        }
};

TEST_F(TestSTResourceManager, st_register_resources)
{
    char *uri = "/capability/switch/main/0";
    oc_resource_t *resource = NULL;
    st_data_mgr_info_load();
    st_register_resources(device_index);
    resource = oc_ri_get_app_resource_by_uri(uri, strlen(uri), device_index);
    EXPECT_STREQ(uri, oc_string(resource->uri));
    st_data_mgr_info_free();
}

TEST_F(TestSTResourceManager, st_register_resource_handler)
{
    st_register_resource_handler(resource_handler, resource_handler);
    // EXPECT_EQ(0, ret);
}

TEST_F(TestSTResourceManager, st_register_resource_handler_fail)
{
    st_register_resource_handler(NULL, NULL);
    // EXPECT_EQ(-1, ret);
}

TEST_F(TestSTResourceManager, st_notify_back)
{
    // Given
    char *uri = "/capability/switch/main/0";
    oc_resource_t *resource = oc_new_resource(NULL, uri, 1, 0);
    oc_resource_bind_resource_type(resource, "core.light");
    oc_add_resource(resource);

    // When
    st_notify_back(uri);
    oc_delete_resource(resource);

    // Then
    // EXPECT_EQ(0, ret);
}

TEST_F(TestSTResourceManager, st_notify_back_fail_null)
{
    // Given
    char *uri = NULL;

    // When
    st_notify_back(uri);

    // Then
    // EXPECT_EQ(-1, ret);
}

TEST_F(TestSTResourceManager, st_notify_back_fail)
{
    // Given
    char *uri = "/capability/switch/main/1";

    // When
    st_notify_back(uri);

    // Then
    // EXPECT_EQ(-1, ret);
}
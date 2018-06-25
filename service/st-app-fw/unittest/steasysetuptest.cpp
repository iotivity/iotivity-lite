#include <gtest/gtest.h>
#include <cstdlib>

extern "C"{
    #include "st_easy_setup.h"
    #include "sc_easysetup.h"
    #include "st_store.h"
    #include "easysetup.h"
    #include "oc_helpers.h"
    #include "st_port.h"
}

#define MAX_SSID_LEN (32)
#define EASYSETUP_TAG "E1"

static const char *device_name = "Samsung";
static const char *manufacturer = "xxxx";
static const char *sid = "000";
static const char *modelNumber = "Model Number";

void easy_setup_handler_test(st_easy_setup_status_t status)
{
    (void)status;
}

class TestSTEasySetup: public testing::Test
{
    protected:
        virtual void SetUp()
        {

        }

        virtual void TearDown()
        {
            st_store_info_initialize();
        }
};

TEST_F(TestSTEasySetup, st_is_easy_setup_finish_O)
{
    st_store_t *store_info = st_store_get_info();
    store_info->status = true;
    int ret = st_is_easy_setup_finish();
    EXPECT_EQ(ret, 0);
}

TEST_F(TestSTEasySetup, st_is_easy_setup_finish_X)
{
    st_store_t *store_info = st_store_get_info();
    store_info->status = false;
    int ret = st_is_easy_setup_finish();
    EXPECT_EQ(ret, -1);
}

TEST_F(TestSTEasySetup, st_easy_setup_start)
{
    sc_properties st_vendor_props;
    memset(&st_vendor_props, 0, sizeof(sc_properties));
    int ret = st_easy_setup_start(&st_vendor_props, easy_setup_handler_test);
    EXPECT_EQ(ret, 0);
    st_easy_setup_stop();
}

TEST_F(TestSTEasySetup, st_easy_setup_stop_reset_sc_properties)
{
    sc_properties g_scprop;
    sc_properties *g_scprop_ptr = NULL;
    memset(&g_scprop, 0, sizeof(sc_properties));
    oc_new_string(&g_scprop.model, modelNumber, strlen(modelNumber));
    set_sc_properties(&g_scprop);
    st_easy_setup_stop();
    g_scprop_ptr = get_sc_properties();

    EXPECT_EQ(g_scprop_ptr, NULL);
}

TEST_F(TestSTEasySetup, st_easy_setup_stop_es_set_state)
{
    es_enrollee_state en_state;
    st_easy_setup_stop();
    en_state = es_get_state();

    EXPECT_EQ(en_state, ES_STATE_INIT);
}

TEST_F(TestSTEasySetup, st_gen_ssid_ret)
{
    char ssid[MAX_SSID_LEN + 1];
    int ret = st_gen_ssid(ssid, device_name, manufacturer, sid);

    EXPECT_EQ(ret, 0);
}

TEST_F(TestSTEasySetup, st_gen_ssid_compare)
{
    unsigned char mac[6] = { 0 };
    oc_get_mac_addr(mac);
    char ssid[MAX_SSID_LEN + 1], expected_ssid[MAX_SSID_LEN + 1];
    snprintf(expected_ssid, MAX_SSID_LEN, "%s_%s%s%s%d%02X%02X", device_name,
           EASYSETUP_TAG, manufacturer, sid, 0, mac[4], mac[5]);
    expected_ssid[strlen(expected_ssid)] = '\0';
    st_gen_ssid(ssid, device_name, manufacturer, sid);

    EXPECT_STREQ(ssid, expected_ssid);
}

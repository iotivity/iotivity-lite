#include <gtest/gtest.h>
#include <cstdlib>

extern "C"{
    #include "st_easy_setup.h"
    #include "st_store.h"
}

TEST(ST_EasySetupTest, st_is_easy_setup_finish)
{
    int ret = st_is_easy_setup_finish();
    EXPECT_EQ(ret, -1);
}
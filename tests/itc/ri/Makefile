SED = sed
INSTALL = install
OS = linux
IOTIVITY_ROOT_DIR = ../../..
OUT_DIR = $(IOTIVITY_ROOT_DIR)/port/$(OS)
MODULE = ri
#CHECK_SCRIPT = ../../tools/check.py


GTEST_DIR = $(IOTIVITY_ROOT_DIR)/deps/gtest
GTEST_HEADERS = $(GTEST_DIR)/include/gtest/*.h \
                $(GTEST_DIR)/include/gtest/internal/*.h
GTEST = gtest_build
TEST_CPPFLAGS += -isystem $(GTEST_DIR)/include
TEST_CXXFLAGS += -g -Wall -Wextra -pthread -std=c++0x -fpermissive -DOC_CLIENT -DOC_SERVER -fprofile-arcs -ftest-coverage
IOTIVITY_HEADER_DIR = $(IOTIVITY_ROOT_DIR)/include

API_TEST_DIR = $(IOTIVITY_ROOT_DIR)/tests/itc/$(MODULE)
API_TEST_OBJ_DIR = $(API_TEST_DIR)/src/obj
API_TEST_HELPER_OBJ_DIR = $(API_TEST_DIR)/helper/obj

API_TEST_HELPER_FILES := $(wildcard $(API_TEST_DIR)/helper/*.cpp)
API_TEST_HEADER_DIR = $(API_TEST_DIR)/include/
API_TEST_SRC_FILES := $(wildcard $(API_TEST_DIR)/src/*.cpp)

API_TEST_OBJ_FILES := $(patsubst $(API_TEST_DIR)/src/%.cpp,$(API_TEST_OBJ_DIR)/%.o,$(API_TEST_SRC_FILES))
API_TEST_HELPER_OBJ_FILES := $(patsubst $(API_TEST_DIR)/helper/%.cpp,$(API_TEST_HELPER_OBJ_DIR)/%.o,$(API_TEST_HELPER_FILES))
INT_TESTS =  integration_test


CONSTRAINED_LIBS = libiotivity-constrained-server.a libiotivity-constrained-client.a \
		   libiotivity-constrained-server.so libiotivity-constrained-client.so \
		   libiotivity-constrained-client-server.so libiotivity-constrained-client-server.a
PC = iotivity-constrained-client.pc iotivity-constrained-server.pc \
     iotivity-constrained-client-server.pc

test: $(INT_TESTS)
all: test

.PHONY: $(GTEST) clean

$(GTEST): $(GTEST_DIR)
	$(MAKE) --directory=$</make

$(API_TEST_HELPER_OBJ_DIR)/%.o: $(API_TEST_DIR)/helper/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(TEST_CPPFLAGS) $(TEST_CXXFLAGS) -I$(IOTIVITY_HEADER_DIR) -I$(IOTIVITY_ROOT_DIR) -I$(API_TEST_HEADER_DIR) -I$(OUT_DIR) -I$(IOTIVITY_ROOT_DIR)/deps/tinycbor/src -c $< -o $@


$(API_TEST_OBJ_DIR)/%.o: $(API_TEST_DIR)/src/%.cpp
	@mkdir -p ${@D}
	$(CXX) $(TEST_CPPFLAGS) $(TEST_CXXFLAGS) -I$(IOTIVITY_HEADER_DIR) -I$(IOTIVITY_ROOT_DIR) -I$(API_TEST_HEADER_DIR) -I$(OUT_DIR) -I$(IOTIVITY_ROOT_DIR)/deps/tinycbor/src -c $< -o $@

integration_test: $(API_TEST_OBJ_FILES) $(API_TEST_HELPER_OBJ_FILES) $(OUT_DIR)/libiotivity-constrained-client-server.a | $(GTEST)
	$(CXX) $(TEST_CPPFLAGS) $(TEST_CXXFLAGS)  -I$(IOTIVITY_HEADER_DIR) -I$(API_TEST_HEADER_DIR) -l:gtest_main.a -liotivity-constrained-client-server -L$(OUT_DIR) -L$(GTEST_DIR)/make -lpthread $^ -o $@


clean:
	rm -rf $(API_TEST_OBJ_FILES) $(API_TEST_HELPER_OBJ_FILES) $(UNIT_TESTS)

cleanall: clean
	rm -rf $(UNIT_TESTS)
	${MAKE} -C ${GTEST_DIR}/make clean



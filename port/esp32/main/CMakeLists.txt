set(includes
    ${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/../adapter/include
	${CMAKE_CURRENT_SOURCE_DIR}/../../..
	${CMAKE_CURRENT_SOURCE_DIR}/../../../include
	${CMAKE_CURRENT_SOURCE_DIR}/../../../messaging/coap
	${CMAKE_CURRENT_SOURCE_DIR}/../../../port
	${CMAKE_CURRENT_SOURCE_DIR}/../../../util
	${CMAKE_CURRENT_SOURCE_DIR}/../../../util/pt
	${CMAKE_CURRENT_SOURCE_DIR}/../../../deps/tinycbor/src
)

set(sources
${CMAKE_CURRENT_SOURCE_DIR}/../../../deps/tinycbor/src/cborencoder.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../deps/tinycbor/src/cborencoder_close_container_checked.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../deps/tinycbor/src/cborparser.c

${CMAKE_CURRENT_SOURCE_DIR}/../../../api/cloud/oc_cloud_apis.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/cloud/oc_cloud_manager.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/cloud/oc_cloud_rd.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/cloud/oc_cloud_resource.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/cloud/oc_cloud_store.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/cloud/oc_cloud.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/cloud/rd_client.c

${CMAKE_CURRENT_SOURCE_DIR}/../adapter/src/random.c
${CMAKE_CURRENT_SOURCE_DIR}/../adapter/src/storage.c
${CMAKE_CURRENT_SOURCE_DIR}/../adapter/src/clock.c
${CMAKE_CURRENT_SOURCE_DIR}/../adapter/src/ipadapter.c
${CMAKE_CURRENT_SOURCE_DIR}/../adapter/src/abort.c
${CMAKE_CURRENT_SOURCE_DIR}/../adapter/src/debug_print.c
${CMAKE_CURRENT_SOURCE_DIR}/../adapter/src/vfs_pipe.c
${CMAKE_CURRENT_SOURCE_DIR}/../adapter/src/tcpadapter.c

${CMAKE_CURRENT_SOURCE_DIR}/../../../util/oc_etimer.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../util/oc_list.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../util/oc_memb.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../util/oc_mmem.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../util/oc_process.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../util/oc_timer.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_base64.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_blockwise.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_buffer.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_client_api.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_collection.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_core_res.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_discovery.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_endpoint.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_helpers.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_introspection.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_main.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_network_events.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_rep.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_ri.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_server_api.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_uuid.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_enums.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_session_events.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../messaging/coap/coap.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../messaging/coap/engine.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../messaging/coap/observe.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../messaging/coap/separate.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../messaging/coap/transactions.c
${CMAKE_CURRENT_SOURCE_DIR}/../../../messaging/coap/coap_signal.c
${CMAKE_CURRENT_SOURCE_DIR}/lightbulb.c
${CMAKE_CURRENT_SOURCE_DIR}/light_bulb_main.c
main.c
)

if (CONFIG_OC_DEBUG)
  add_definitions(-DOC_DEBUG)
endif()

if (CONFIG_IPV4)
  add_definitions(-DOC_IPV4)
endif()

if (CONFIG_TCP)
  add_definitions(-DOC_TCP)
endif()

if (CONFIG_CLOUD)
  add_definitions(-DOC_CLOUD -DOC_DYNAMIC_ALLOCATION -DOC_TCP -DOC_IPV4)
endif()

if (CONFIG_DYNAMIC)
	add_definitions(-DOC_DYNAMIC_ALLOCATION)
endif()

#add_definitions(-DOC_CLIENT)
#add_definitions(-DOC_SERVER)

idf_component_register(
	SRCS
		${sources}
	INCLUDE_DIRS
		${includes}
)

set_source_files_properties(${sources}
   PROPERTIES COMPILE_FLAGS
    "-DOC_SERVER -DOC_CLIENT"
)

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
  list(APPEND sources
  	${CMAKE_CURRENT_SOURCE_DIR}/../adapter/src/tcpadapter.c
	${CMAKE_CURRENT_SOURCE_DIR}/../../../messaging/coap/coap_signal.c
  )
endif()

if (CONFIG_CLOUD)
  add_definitions(-DOC_CLOUD -DOC_DYNAMIC_ALLOCATION -DOC_TCP -DOC_IPV4)
  list(APPEND sources
  	${CMAKE_CURRENT_SOURCE_DIR}/../../../api/cloud/oc_cloud_apis.c
	${CMAKE_CURRENT_SOURCE_DIR}/../../../api/cloud/oc_cloud_manager.c
	${CMAKE_CURRENT_SOURCE_DIR}/../../../api/cloud/oc_cloud_rd.c
	${CMAKE_CURRENT_SOURCE_DIR}/../../../api/cloud/oc_cloud_resource.c
	${CMAKE_CURRENT_SOURCE_DIR}/../../../api/cloud/oc_cloud_store.c
	${CMAKE_CURRENT_SOURCE_DIR}/../../../api/cloud/oc_cloud.c
	${CMAKE_CURRENT_SOURCE_DIR}/../../../api/cloud/rd_client.c
  )
endif()

if (CONFIG_DYNAMIC)
	add_definitions(-DOC_DYNAMIC_ALLOCATION)
	list(APPEND sources
	${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_collection.c
	)
endif()

if (CONFIG_SECURE)
	add_definitions(-DOC_SECURITY -DOC_PKI -DAPP_DEBUG)
	list(APPEND sources
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_acl.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_ael.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_audit.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_certs.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_cred.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_csr.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_doxm.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_keypair.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_obt.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_obt_certs.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_obt_otm_cert.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_obt_otm_justworks.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_obt_otm_randompin.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_pki.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_pstat.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_roles.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_sdi.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_sp.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_store.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_svr.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../security/oc_tls.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../api/oc_clock.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../api/c-timestamp/timestamp_format.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../api/c-timestamp/timestamp_tm.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../api/c-timestamp/timestamp_valid.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../api/c-timestamp/timestamp_parse.c
		${CMAKE_CURRENT_SOURCE_DIR}/../../../api/c-timestamp/timestamp_compare.c
	)
endif()

#add_definitions(-DOC_CLIENT)
#add_definitions(-DOC_SERVER)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-format-truncation")

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

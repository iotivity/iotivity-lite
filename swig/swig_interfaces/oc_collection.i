/* File oc_api.i */
%module OCCollectionUtil
%include iotivity.swg

%{
#include "oc_collection.h"
%}

/*******************Begin oc_collection.h*******************/
typedef struct oc_link_s oc_link_t;
%rename(OCLink) oc_link_s;
typedef struct oc_collection_s oc_collection_t;
%rename(OCCollection) oc_collection_s;
%rename(handleCollectionRequest) oc_handle_collection_request;
%rename(newCollection) oc_collection_alloc;
%rename(freeCollection) oc_collection_free;
%rename(getCollectionByUri) oc_get_collection_by_uri;
%rename(collectionGetAll) oc_collection_get_all;
%rename(getLinkByUri) oc_get_link_by_uri;
%rename(checkIfCollection) oc_check_if_collection;
%rename(collectionAdd) oc_collection_add;
%include "oc_collection.h"
/*******************End oc_collection.h*********************/
/* File oc_api.i */
%module OCCollectionUtil

%include "stdint.i"
%include iotivity.swg

%import oc_ri.i
%import oc_uuid.i

%{
#include "oc_collection.h"
%}

/*******************Begin oc_collection.h*******************/
typedef struct oc_link_s oc_link_t;
%rename(OCLink) oc_link_s;
typedef struct oc_collection_s oc_collection_t;
%ignore oc_collection_s::get_handler;
%ignore oc_collection_s::put_handler;
%ignore oc_collection_s::post_handler;
%ignore oc_collection_s::delete_handler;
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
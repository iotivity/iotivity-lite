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
%rename(OCLinkParams) oc_link_params_t;
%rename(OCLink) oc_link_t;
%ignore oc_link_t::OC_LIST_STRUCT(params);
%extend oc_link_t {
  oc_link_params_t *getParamsListHead() {
    return oc_list_head(self->params);
  }
}
%rename(OCResourceType) oc_rt_t;
%ignore oc_collection_t::get_handler;
%ignore oc_collection_t::put_handler;
%ignore oc_collection_t::post_handler;
%ignore oc_collection_t::delete_handler;
%ignore oc_collection_t::get_properties;
%ignore oc_collection_t::set_properties;
%rename (numLinks) oc_collection_t::num_links;
%ignore oc_collection_t::OC_LIST_STRUCT(mandatory_rts);
// TODO convert to array of strings.
%extend oc_collection_t {
  oc_rt_t *getMandatoryResourceTypesListHead() {
    return oc_list_head(self->mandatory_rts);
  }
}
%ignore oc_collection_t::OC_LIST_STRUCT(supported_rts);
// TODO conver to array of strings
%extend oc_collection_t {
  oc_rt_t *getSupportedResourceTypesListHead() {
    return oc_list_head(self->supported_rts);
  }
}
%ignore oc_collection_t::OC_LIST_STRUCT(links);
%extend oc_collection_t {
  oc_link_t *getLinksListHead() {
    return oc_list_head(self->links);
  }
}
%rename(OCCollection) oc_collection_t;
%rename(handleCollectionRequest) oc_handle_collection_request;
%rename(newCollection) oc_collection_alloc;
%rename(freeCollection) oc_collection_free;
%rename(getNextCollectionWithLink) oc_get_next_collection_with_link;
%rename(getCollectionByUri) oc_get_collection_by_uri;
%rename(collectionGetAll) oc_collection_get_all;
%rename(getLinkByUri) oc_get_link_by_uri;
%rename(checkIfCollection) oc_check_if_collection;
%rename(collectionAdd) oc_collection_add;
%include "oc_collection.h"
/*******************End oc_collection.h*********************/

/* File oc_api.i */
%module OCCollectionUtil

%include "stdint.i";
%include "arrays_java.i";
%include "iotivity.swg";

%import "oc_ri.i";
%import "oc_uuid.i";
%import "oc_enums.i";

%{
#include "oc_collection.h"
%}

/*******************Begin oc_collection.h*******************/
%rename(OCLinkParams) oc_link_params_t;
typedef struct oc_link_s oc_link_t;
%rename(OCLink) oc_link_s;
%ignore oc_link_s::OC_LIST_STRUCT(params);
%extend oc_link_s {
  oc_link_params_t *getParamsListHead() {
    return oc_list_head(self->params);
  }
}
%rename(OCResourceType) oc_rt_t;
typedef struct oc_collection_s oc_collection_t;
%ignore oc_collection_s::get_handler;
%ignore oc_collection_s::put_handler;
%ignore oc_collection_s::post_handler;
%ignore oc_collection_s::delete_handler;
%ignore oc_collection_s::get_properties;
%ignore oc_collection_s::set_properties;
%rename(tagPositionRelative) oc_collection_s::tag_pos_rel;
%rename(tagPositionDescription) oc_collection_s::tag_pos_desc;
%rename(tagPositionFunction) oc_collection_s::tag_pos_func;
%rename (numLinks) oc_collection_s::num_links;
%ignore oc_collection_s::OC_LIST_STRUCT(mandatory_rts);
// TODO convert to array of strings.
%extend oc_collection_s {
  oc_rt_t *getMandatoryResourceTypesListHead() {
    return oc_list_head(self->mandatory_rts);
  }
}
%ignore oc_collection_s::OC_LIST_STRUCT(supported_rts);
// TODO conver to array of strings
%extend oc_collection_s {
  oc_rt_t *getSupportedResourceTypesListHead() {
    return oc_list_head(self->supported_rts);
  }
}
%ignore oc_collection_s::OC_LIST_STRUCT(links);
%extend oc_collection_s {
  oc_link_t *getLinksListHead() {
    return oc_list_head(self->links);
  }
}
%rename(OCCollection) oc_collection_s;
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
/* File oc_link.i */
%module OCLinkUtil

%include "stdint.i";
%include "iotivity.swg";

%import "oc_ri.i"

%{
#include "api/oc_link_internal.h"
#include "oc_link.h"
%}

/*******************Begin oc_link.h*******************/

%rename(OCLinkParams) oc_link_params_t;
typedef struct oc_link_s oc_link_t;
%rename(OCLink) oc_link_s;
%ignore oc_link_s::OC_LIST_STRUCT(params);
%extend oc_link_s {
  oc_link_params_t *getParamsListHead() {
    return oc_list_head(self->params);
  }
}


// DOCUMENTATION workaround
%javamethodmodifiers oc_new_link "/**
   * Creates a new link for collections with the specified resource.
   *
   * @param resource Resource to set in the link. The resource is not copied.
   *  Must not be NULL
   *
   * @return The created link or NULL if out of memory or resource is NULL.
   *
   * @see deleteLink
   * @see collectionAddLink
   * @see newResource
   */
  public";
%rename(newLink) oc_new_link;

// DOCUMENTATION workaround
%javamethodmodifiers oc_delete_link "/**
   * Deletes the link.
   * <p>
   * <strong>Note</strong>: the function neither removes the resource set on this link
   *  nor does it remove it from any collection.
   *
   * @param link The link to delete. The function does nothing, if
   *  the parameter is NULL
   */
  public";
%rename(deleteLink) oc_delete_link;

// DOCUMENTATION workaround
%javamethodmodifiers oc_link_add_rel "/**
   * Adds a relation to the link.
   *
   * @param link Link to add the relation to. Must not be null
   * @param rel Relation to add. Must not be null
   */
  public";
%rename(linkAddRelation) oc_link_add_rel;

// DOCUMENTATION workaround
%javamethodmodifiers oc_link_add_link_param "/**
   * Adds a link parameter with specified key and value.
   *
   * @param link Link to which to add a link parameter. Must not be null.
   * @param key Key to identify the link parameter. Must not be null.
   * @param value Link parameter value. Must not be null.
   */
  public";
%rename(linkAddLinkParameter) oc_link_add_link_param;

#define OC_API
#define OC_NONNULL(...)
%include "api/oc_link_internal.h"
%include "oc_link.h"
/*******************End oc_link.h*********************/

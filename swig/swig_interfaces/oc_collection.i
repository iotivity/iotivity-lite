/* File oc_collection.i */
%module OCCollectionUtil

%include "stdint.i";
%include "typemaps.i"
%include "iotivity.swg";

#define OC_DYNAMIC_ALLOCATION
%include "oc_config.h"

%import "oc_link.i"
%import "oc_ri.i"

%{
#include "api/oc_collection_internal.h"
#include "oc_collection.h"
%}


/*******************Begin oc_collection.h*******************/

/* Code and typemaps for mapping the oc_get_properties_cb_t to the java OCGetPropertiesHandler */
%{
void jni_oc_get_properties_callback(const oc_resource_t *resource, oc_interface_mask_t iface_mask, void *user_data) {
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = get_jni_env(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCGetPropertiesHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCGetPropertiesHandler,
                                       "handler",
                                       "(Lorg/iotivity/OCResource;I)V");
  assert(mid_handler);

  jobject jresource = NULL;
  if (resource) {
    assert(cls_OCResource);
    const jmethodID mid_OCResource_init = JCALL3(GetMethodID, (data->jenv), cls_OCResource, "<init>", "(JZ)V");
    assert(mid_OCResource_init);
    jresource = JCALL4(NewObject, (data->jenv), cls_OCResource, mid_OCResource_init, (jlong)resource, false);
  }
  JCALL4(CallVoidMethod,
         (data->jenv),
         data->jcb_obj,
         mid_handler,
         jresource,
         (jint)iface_mask);

  if (data->cb_valid == OC_CALLBACK_VALID_FOR_A_SINGLE_CALL) {
    jni_list_remove(data);
  }

  release_jni_env(getEnvResult);
}
%}
%typemap(jni)    oc_get_properties_cb_t getPropertiesHandler "jobject";
%typemap(jtype)  oc_get_properties_cb_t getPropertiesHandler "OCGetPropertiesHandler";
%typemap(jstype) oc_get_properties_cb_t getPropertiesHandler "OCGetPropertiesHandler";
%typemap(javain) oc_get_properties_cb_t getPropertiesHandler "$javainput";
%typemap(in,numinputs=1) (oc_get_properties_cb_t getPropertiesHandler, jni_callback_data *get_properties_jcb)
{
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  // see jni_delete_resource for the deletion of the GlobalRef in the jni_list_remove calls
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
  jni_list_add(user_data);
  $1 = jni_oc_get_properties_callback;
  $2 = user_data;
}

/* Code and typemaps for mapping the oc_set_properties_cb_t to the java OCSetPropertiesHandler */
%{
bool jni_oc_set_properties_callback(const oc_resource_t *resource, const oc_rep_t *rep, void *user_data) {
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = get_jni_env(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCSetPropertiesHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCSetPropertiesHandler,
                                       "handler",
                                       "(Lorg/iotivity/OCResource;Lorg/iotivity/OCRepresentation;)Z");
  assert(mid_handler);

  jobject jresource = NULL;
  if (resource) {
    assert(cls_OCResource);
    const jmethodID mid_OCResource_init = JCALL3(GetMethodID, (data->jenv), cls_OCResource, "<init>", "(JZ)V");
    assert(mid_OCResource_init);
    jresource = JCALL4(NewObject, (data->jenv), cls_OCResource, mid_OCResource_init, (jlong)resource, false);
  }

  jobject jrep = NULL;
  if (rep) {
    assert(cls_OCRepresentation);
    const jmethodID mid_OCRepresentation_init = JCALL3(GetMethodID,
                                                       (data->jenv),
                                                       cls_OCRepresentation, "<init>",
                                                       "(JZ)V");
    assert(mid_OCRepresentation_init);
    jrep = JCALL4(NewObject, (data->jenv), cls_OCRepresentation, mid_OCRepresentation_init, (jlong)rep, false);
  }

  bool returnValue = JCALL4(CallBooleanMethod,
                            (data->jenv),
                            data->jcb_obj,
                            mid_handler,
                            jresource,
                            jrep);

  if (data->cb_valid == OC_CALLBACK_VALID_FOR_A_SINGLE_CALL) {
    jni_list_remove(data);
  }

  release_jni_env(getEnvResult);
  return returnValue;
}
%}
%typemap(jni)    oc_set_properties_cb_t setPropertiesHandler "jobject";
%typemap(jtype)  oc_set_properties_cb_t setPropertiesHandler "OCSetPropertiesHandler";
%typemap(jstype) oc_set_properties_cb_t setPropertiesHandler "OCSetPropertiesHandler";
%typemap(javain) oc_set_properties_cb_t setPropertiesHandler "$javainput";
%typemap(in,numinputs=1) (oc_set_properties_cb_t setPropertiesHandler, jni_callback_data *set_properties_jcb)
{
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  // see jni_delete_resource for the deletion of the GlobalRef in the jni_list_remove calls
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
  jni_list_add(user_data);
  $1 = jni_oc_set_properties_callback;
  $2 = user_data;
}

%ignore oc_resource_set_properties_cbs;
%rename(resourceSetPropertiesHandlers) jni_resource_set_properties_cbs;
%inline %{
void jni_resource_set_properties_cbs(oc_resource_t *resource,
                                     oc_get_properties_cb_t getPropertiesHandler,
                                     jni_callback_data *get_properties_jcb,
                                     oc_set_properties_cb_t setPropertiesHandler,
                                     jni_callback_data *set_properties_jcb) {
  OC_DBG("JNI: %s\n", __func__);
  oc_resource_set_properties_cbs(resource, getPropertiesHandler, get_properties_jcb, setPropertiesHandler, set_properties_jcb);
}
%}


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
%rename(getCollectionByUri) oc_get_collection_by_uri;
%rename(getLinkByUri) oc_get_link_by_uri;
%rename(checkIfCollection) oc_check_if_collection;

// DOCUMENTATION workaround
%javamethodmodifiers oc_new_collection "/**
   * Creates a new empty collection.
   * <p>
   * The collection is created with interfaces `oic.if.baseline`,
   * `oic.if.ll` (also default) and `oic.if.b`. Initially it is neither
   * discoverable nor observable.
   * <p>
   * The function only allocates the collection. Use addCollection() after the
   * setup of the collection is complete.
   *
   * @param name name of the collection
   * @param uri Unique URI of this collection. Must not be NULL
   * @param num_resource_types Number of resources the caller will bind with this resource
   *                           (e.g. by invoking resourceBindResourceType(col, OIC_WK_COLLECTION)).
   *                           Must be 1 or higher
   * @param device The internal device that should carry this collection. This is typically 0
   * @return the new collection or NULL if out of memory.
   * @see addCollection
   * @see collectionAddLink
   */
  public";
%rename(newCollection) oc_new_collection;

// DOCUMENTATION workaround
%javamethodmodifiers oc_delete_collection "/**
   * Deletes the specified collection.
   * <p>
   * The function removes the collection from the internal list of collections
   * and releases all direct resources and links associated with this collection.
   * <p>
   * Note: The function does not delete the resources set in the links.
   *  The caller needs to do this on their own in case these are
   *  no longer required.
   *
   * @param collection The pointer to the collection to delete.
   *                   If this is NULL, the function does nothing
   *
   * @see collectionGetLinks
   * @see deleteLink
   */
  public";
%rename(deleteCollection) oc_delete_collection;

%rename(addCollection) oc_add_collection;

// DOCUMENTATION workaround
%javamethodmodifiers oc_add_collection_v1 "/**
   * Adds a collection to the list of collections.
   * <p>
   * If the caller makes the collection discoverable, then it will
   * be included in the collection discovery once it has been added
   * with this function.
   * <p>
   * The collection must not be null. Must not be added twice or a list corruption
   * will occur. The collection is not copied.
   *
   * @param collection Collection to add to the list of collections
   *
   * @see resourceSetDiscoverable
   * @see newCollection
   */
  public";
%rename(addCollectionV1) oc_add_collection_v1;


// DOCUMENTATION workaround
%javamethodmodifiers oc_collection_add_link "/**
   * Adds the link to the collection.
   * <p>
   * The collection and link must not be null.
   * <p>
   * The link is not copied. The link Must not be added again to this or a
   * different collection; this will cause a list corruption to occur. To re-add
   * a link, remove the link first.
   *
   * @param collection Collection to add the link to. Must not be NULL.
   * @param link Link to add to the collection
   *
   * @see newLink
   * @see collectionRemoveLink
   */
  public";
%rename(collectionAddLink) oc_collection_add_link;

// DOCUMENTATION workaround
%javamethodmodifiers oc_collection_remove_link "/**
   * Removes a link from the collection.
   * <p>
   * Does nothing if the collection or link is null.
   * <p>
   * Does nothing if the link is not part of the collection.
   * <p>
   * @param collection Collection to remove the link from
   * @param link The link to remove
   */
  public";
%rename(collectionRemoveLink) oc_collection_remove_link;

// DOCUMENTATION workaround
%javamethodmodifiers oc_collection_get_links "/**
   * Returns the list of links belonging to this collection.
   *
   * @param collection Collection to get the links from.
   *
   * @return All links of this collection. The links are not copied. Returns
   *  null if the collection is null or contains no links.
   *
   * @see collectionAddLink
   */
  public";
%rename(collectionGetLinks) oc_collection_get_links;

// DOCUMENTATION workaround
%javamethodmodifiers oc_collection_get_collections "/**
   * Gets all known collections.
   *
   * @return All collections that have been added via addCollection(). The
   * collections are not copied.  Returns null if there are no collections.
   * Collections created using newCollection() but not added will not be
   * returned by this method.
   */
  public";
%rename(collectionGetCollections) oc_collection_get_collections;
%rename(collectionAddSupportedResourceType) oc_collection_add_supported_rt;
%rename(collectionAddMandatoryResourceType) oc_collection_add_mandatory_rt;

#define OC_API
#define OC_DEPRECATED(...)
#define OC_NO_DISCARD_RETURN
#define OC_NONNULL(...)
%include "oc_collection.h"
/*******************End oc_collection.h*********************/

/*******************Begin oc_collection_internal.h*******************/
%ignore oc_collection_alloc;
%ignore oc_collection_free;
%ignore oc_collection_add;
%ignore oc_collection_get_all;
%ignore oc_get_next_collection_with_link;
%ignore oc_handle_collection_request;

%include "api/oc_collection_internal.h"
/*******************End oc_collection_internal.h*********************/

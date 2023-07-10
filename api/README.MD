# Features

## Entity Tag (ETAG): Tracking Resource Changes

To utilize this feature, you must enable `OC_ETAG`.

The Entity Tag (ETAG) mechanism allows clients to determine if a resource has been modified since its last access. There are two methods for updating the ETAG when a resource changes:

- `oc_notify_observers`: Notifies all observers that the resource has changed and calls `oc_resource_update_etag`.
- `oc_resource_update_etag`: Updates the ETAG for non-observable resources.

For each resource, an ETAG is stored, represented either as the epoch time in milliseconds (`oc_clock_time()`) or as the highest ETAG value plus 1 if the epoch time is less than the current highest ETAG value. Enabling `OC_STORAGE` is necessary for ETAG availability after device restart.

During device startup, the device developer loads the ETAGs using `oc_etag_load_and_clear` via the public API and clears the existing storage. Additionally, when properly shutting down iotivity-lite, the ETAGs are stored in the storage using `oc_etag_dump` via the public API. Improper shutdown results in the ETAGs not being stored, leading to their absence upon restart. The device developer should call `oc_etag_load_and_clear` after creating all resources and before calling `oc_main_init`, and `oc_etag_dump` before calling `oc_main_shutdown`.

### GET/Observations

When creating or closing an observation, the client can include the latest ETAG to request. If the ETAG is equal to the resource's latest ETAG, the device responds with a `VALID` code and an empty body. If the ETAG is not equal to the resource's latest ETAG, the device responds with a `CONTENT` code and the content along with the latest ETAG. Subsequent observation notifications will contain the ETAG value from the resource.

#### Batch Observation over /oic/res

Similar to regular observations, but the ETAG value used is the highest ETAG value among all device resources in the collection.

### Edge Cases

1. Time Synchronization: Ensuring proper time synchronization is crucial for accurate generation of epoch time used in ETAGs. Inconsistent system clock synchronization can lead to disparities when comparing ETAG values. To address this, if the epoch time is less than the current ETAG value, the highest ETAG value plus 1 is used as a mitigation strategy.
2. Storage Failure: If storing ETAG values fails, it can result in the loss of ETAG information and inconsistencies when determining resource modification. To mitigate this issue, the device developer should verify the return value from `oc_etag_dump` to confirm the success of the operation. Storage failures often occur due to insufficient storage space.
3. ETAG Reset: In the event of a system restart or power outage, the highest ETAG value stored in memory may be lost. To mitigate this, the ETAG values are not loaded through `oc_etag_load_and_clear`, requiring the client to resynchronize with the device.
4. Absence of Resources after Device Reboot: ETAG values for non-existing resources are considered when calculating the highest ETAG value. This ensures that ETAG values are not reused by new resources, avoiding conflicts and maintaining consistency.
5. Addition of Resources after Device Reboot: Similar to creating a new resource, the ETAG value for a newly added resource is set either as the epoch time in milliseconds (`oc_clock_time()`) or as the highest ETAG value plus 1 if the epoch time is less than the current highest ETAG value. This ensures proper tracking of changes for the newly added resource.

## Dynamic and static allocation

Whether dynamic or static allocation is enabled is determined by the macro `OC_DYNAMIC_ALLOCATION`.

It effects the structures that are aliases of `struct oc_mmem` (`oc_handle_t`, `oc_string_t`, `oc_array_t`, `oc_string_array_t,` and `oc_byte_string_array_t`), which are allocated by `_oc_mmem_alloc` and deallocated by `_oc_mmem_free`.

With dynamic allocation standard `malloc` and `free` calls are used.

### Static allocation

With static allocation preallocated static buffers are used.

Allocation:

* Take the desired number of bytes from the start of the unused part of the static buffer (if there are not enough available bytes in the buffer then `NULL` is returned)
* Append the allocated variable to a global linked list of allocated variables

Deallocation:

* Reallocate data of all variables allocated after the variable currently being deallocated (ie they appear later in the global linked list) and write over the bytes previously used by the deallocated variable.
* Increase the number of available bytes in the static buffer by the size of the deallocated variable.

#### Pitfalls

* Be careful when passing `oc_handle_t`, `oc_string_t`, `oc_array_t`, `oc_string_array_t,` and `oc_byte_string_array_t` by value.

On allocation the pointer of the allocated variable is stored in the global linked list of allocations. If you copy a variable by value then pointer to this copy won't be in the global linked list and if you attempt a deallocation with this copy you will cause memory corruption.

Invalid code:

```C
oc_string_t str1;
oc_new_string(&str, "test", strlen("test"));

oc_string_t str2 = str1;
oc_free_string(&str2); // error, memory corruption

```

Valid code:

```C
oc_string_t str1;
oc_new_string(&str, "test", strlen("test"));

oc_string_t str2;
oc_copy_string(&str2, &str1);
```

* Be careful when storing pointer to internal data of a `oc_handle_t`, `oc_string_t`, `oc_array_t`, `oc_string_array_t,` and `oc_byte_string_array_t` variable.

If you store a pointer to internal data of a variable and then another variable, that has been allocated sooner is deallocated, then the stored pointer is invalidated.

Invalid code:

```C
oc_string_t first;
oc_new_string(&first, "first", strlen("first"));

oc_string_t second;
oc_new_string(&second, "second", strlen("second"));


const char* second_str = oc_string(second);
oc_free_string(&first); // second_str is now invalidated, because the variable second was allocated later and thus its internal data is reallocated after the variable first is deallocated

printf("%s", second_str);
```

Valid code:

```C
oc_string_t first;
oc_new_string(&first, "first", strlen("first"));

oc_string_t second;
oc_new_string(&second, "second", strlen("second"));

oc_free_string(&first);
printf("%s", oc_string(second));
```

## Resources (Server API)

### Add a resource

To create and initialize a new resource instance use:

```C
oc_resource_t *oc_new_resource(const char *name, const char *uri, uint8_t num_resource_types, size_t device);
```

To futher configure the resource examine the following functions:

* `oc_resource_bind_resource_interface`
* `oc_resource_set_default_interface`
* `oc_resource_bind_resource_type`
* `oc_resource_tag_pos_desc`
* `oc_resource_tag_pos_rel`
* `oc_resource_tag_func_desc`
* `oc_resource_tag_locn`
* `oc_resource_make_public`
* `oc_resource_set_discoverable`
* `oc_resource_set_pushable`
* `oc_resource_set_observable`
* `oc_resource_set_periodic_observable`
* `oc_resource_set_request_handler`

To add the created resource to the application you must call `oc_ri_add_resource`. The resource will now be available to configured request handlers (CREATE/GET/POST/PUT/DELETE).

### Delete a resource

To remove a resource from the application and deallocate its data use:

```C
bool oc_ri_delete_resource(oc_resource_t *resource);
```

However, this function shouldn't always be used directly. The paradigmatic case when it should be avoided is from the DELETE request handler. The processing of a request that occurrs after the DELETE request handler invocation still uses some resource data. Therefore `oc_ri_delete_resource` must only be called after the processing of the request is done.

#### Delete a resource from a DELETE request handler

To solve this issue use:

```C
void oc_delayed_delete_resource(oc_resource_t *resource)
```

Which schedules `oc_ri_delete_resource` in a delayed callback, which guarantees that the deallocation will occur on the next tick of the main run loop.

If you need to deallocate some custom data associated with the `oc_resource_t*` that is about to be deallocated, or do some other operation before the resource is deallocated then you can use `oc_ri_on_delete_resource_add_callback` to add a callback which will be invoked with resource just before the call to `oc_ri_delete_resource`.

<!-- ## Collections -->

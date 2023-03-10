# Features

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

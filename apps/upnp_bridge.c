/*
 // Copyright (c) 2020 Intel Corporation
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
 // You may obtain a copy of the License at
 //
 //      http://www.apache.org/licenses/LICENSE-2.0
 //
 // Unless required by applicable law or agreed to in writing, software
 // distributed under the License is distributed on an "AS IS" BASIS,
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
 */

#include "oc_api.h"
#include "oc_bridge.h"
#include "port/oc_clock.h"
#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <pthread.h>
#else
#error "Unsupported OS"
#endif
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <glib.h>
#include <gupnp-control-point.h>
#include <gupnp-device-proxy.h>
#include <gupnp-service-proxy.h>

#if defined(_WIN32)
static HANDLE event_thread;
static CRITICAL_SECTION app_sync_lock;
static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;

/* OS specific definition for lock/unlock */
#define app_mutex_lock(m) EnterCriticalSection(&m)
#define app_mutex_unlock(m) LeaveCriticalSection(&m)

#elif defined(__linux__)
static pthread_t event_thread;
static pthread_mutex_t app_sync_lock;
static pthread_mutex_t mutex;
static pthread_cond_t cv;

/* OS specific definition for lock/unlock */
#define app_mutex_lock(m) pthread_mutex_lock(&m)
#define app_mutex_unlock(m) pthread_mutex_unlock(&m)

static struct timespec ts;
#endif

int quit = 0;
GMainLoop *s_main_loop = NULL;
GHashTable *s_resource_lookup = NULL;

static void get_switch(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data) {
    GUPnPServiceProxy *proxy = (GUPnPServiceProxy*) user_data;
    PRINT("GET_Switch\n");

    bool switchValue = false;
    GError *error = NULL;
    if (!gupnp_service_proxy_send_action(proxy, "GetTarget", &error, NULL, "RetTargetValue", G_TYPE_BOOLEAN,
            &switchValue, NULL)) {
        PRINT("UPnP GetTarget action failed\n");
        if (error) {
            PRINT("Error message: %s\n", error->message);
            g_error_free(error);
        }
        oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
        return;
    }

    oc_status_t response = OC_STATUS_OK;
    oc_rep_begin_root_object();
    switch (iface_mask) {
    case OC_IF_BASELINE:
        oc_process_baseline_interface(request->resource);
        /* fall through */
    case OC_IF_A:
    case OC_IF_RW:
        oc_rep_set_boolean(root, value, switchValue);
        break;
    default:
        response = OC_STATUS_BAD_REQUEST;
        break;
    }
    oc_rep_end_root_object();
    PRINT("Switch value=%s\n", (switchValue ? "true" : "false"));
    oc_send_response(request, response);
}

static void post_switch(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data) {
    (void) iface_mask;
    GUPnPServiceProxy *proxy = (GUPnPServiceProxy*) user_data;
    PRINT("POST_Switch\n");

    bool switchValue = false;
    oc_rep_t *rep = request->request_payload;
    while (rep) {
        PRINT("key=%s, rep type=%d\n", (rep->name).ptr, rep->type);
        char *key = (char*) (rep->name).ptr;
        if (strncmp(key, "value", (rep->name).size) == 0) {
            switch (rep->type) {
            case OC_REP_BOOL:
                switchValue = rep->value.boolean;
                PRINT("New value=%s\n", (switchValue ? "true" : "false"));
                break;
            default:
                PRINT("Unexpected rep type: %d\n", rep->type);
                oc_send_response(request, OC_STATUS_BAD_REQUEST);
                return;
            }
        }
        rep = rep->next;
    }

    GError *error = NULL;
    if (!gupnp_service_proxy_send_action(proxy, "SetTarget", &error, "newTargetValue", G_TYPE_BOOLEAN, switchValue,
            NULL, NULL)) {
        PRINT("UPnP SetTarget action failed\n");
        if (error) {
            PRINT("Error message: %s\n", error->message);
            g_error_free(error);
        }
        oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
        return;
    }

    PRINT("Set value=%s\n", (switchValue ? "true" : "false"));
    oc_send_response(request, OC_STATUS_CHANGED);
}

static void put_switch(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data) {
    PRINT("PUT_Switch\n");
    post_switch(request, iface_mask, user_data);
}

static void get_dimming(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data) {
    GUPnPServiceProxy *proxy = (GUPnPServiceProxy*) user_data;
    PRINT("GET_Dimming\n");

    int dimmingValue = 0;
    GError *error = NULL;
    if (!gupnp_service_proxy_send_action(proxy, "GetLoadLevelTarget", &error, NULL, "retLoadlevelTarget", G_TYPE_INT,
            &dimmingValue, NULL)) {
        PRINT("UPnP GetLoadLevelTarget action failed\n");
        if (error) {
            PRINT("Error message: %s\n", error->message);
            g_error_free(error);
        }
        oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
        return;
    }

    oc_status_t response = OC_STATUS_OK;
    oc_rep_begin_root_object();
    switch (iface_mask) {
    case OC_IF_BASELINE:
        oc_process_baseline_interface(request->resource);
        /* fall through */
    case OC_IF_A:
    case OC_IF_RW:
        oc_rep_set_int(root, dimmingSetting, dimmingValue);
        break;
    default:
        response = OC_STATUS_BAD_REQUEST;
        break;
    }
    oc_rep_end_root_object();
    PRINT("Dimming value=%d\n", dimmingValue);
    oc_send_response(request, response);
}

static void post_dimming(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data) {
    (void) iface_mask;
    GUPnPServiceProxy *proxy = (GUPnPServiceProxy*) user_data;
    PRINT("POST_Dimming\n");

    int dimmingValue = 0;
    oc_rep_t *rep = request->request_payload;
    while (rep) {
        PRINT("key=%s, rep type=%d\n", (rep->name).ptr, rep->type);
        char *key = (char*) (rep->name).ptr;
        if (strncmp(key, "dimmingSetting", (rep->name).size) == 0) {
            switch (rep->type) {
            case OC_REP_INT:
                dimmingValue = rep->value.integer;
                PRINT("New dimming value=%d\n", dimmingValue);
                break;
            default:
                PRINT("Unexpected rep type: %d\n", rep->type);
                oc_send_response(request, OC_STATUS_BAD_REQUEST);
                return;
            }
        }
        rep = rep->next;
    }

    GError *error = NULL;
    if (!gupnp_service_proxy_send_action(proxy, "SetLoadLevelTarget", &error, "newLoadlevelTarget", G_TYPE_INT,
            dimmingValue, NULL, NULL)) {
        PRINT("UPnP SetLoadLevelTarget action failed\n");
        if (error) {
            PRINT("Error message: %s\n", error->message);
            g_error_free(error);
        }
        oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
        return;
    }

    PRINT("Set dimming value=%d\n", dimmingValue);
    oc_send_response(request, OC_STATUS_CHANGED);
}

static void put_dimming(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data) {
    PRINT("PUT_Dimming\n");
    post_switch(request, iface_mask, user_data);
}

void register_binary_switch_resource(const char *name, const char *uri, size_t device_index, void *user_data) {
    // user_data is the service proxy
    oc_resource_t *res = oc_new_resource(name, uri, 1, device_index);
    oc_resource_bind_resource_type(res, "oic.r.switch.binary");
    oc_resource_bind_resource_interface(res, OC_IF_A);
    oc_resource_set_default_interface(res, OC_IF_A);
    oc_resource_set_discoverable(res, true);
    oc_resource_set_observable(res, true);
    oc_resource_set_request_handler(res, OC_GET, get_switch, user_data);
    oc_resource_set_request_handler(res, OC_POST, post_switch, user_data);
    oc_resource_set_request_handler(res, OC_PUT, put_switch, user_data);
    oc_add_resource(res);
    g_hash_table_insert(s_resource_lookup, user_data, res); // add to resource lookup
}

void register_light_dimming_resource(const char *name, const char *uri, size_t device_index, void *user_data) {
    // user_data is the service proxy
    oc_resource_t *res = oc_new_resource(name, uri, 1, device_index);
    oc_resource_bind_resource_type(res, "oic.r.light.dimming");
    oc_resource_bind_resource_interface(res, OC_IF_A);
    oc_resource_set_default_interface(res, OC_IF_A);
    oc_resource_set_discoverable(res, true);
    oc_resource_set_observable(res, true);
    oc_resource_set_request_handler(res, OC_GET, get_dimming, user_data);
    oc_resource_set_request_handler(res, OC_POST, post_dimming, user_data);
    oc_resource_set_request_handler(res, OC_PUT, put_dimming, user_data);
    oc_add_resource(res);
    g_hash_table_insert(s_resource_lookup, user_data, res); // add to resource lookup
}

void remove_resource(oc_resource_t *resource) {
    if (resource) {
        oc_resource_set_discoverable(resource, false);
        oc_resource_set_observable(resource, false);
        oc_delete_resource(resource);
    }
}

// Callback: rescan for devices and services
static gboolean rescan_callback(gpointer user_data) {
    if (user_data) {
        GUPnPControlPoint *control_point = (GUPnPControlPoint *) user_data;
        gssdp_resource_browser_rescan(GSSDP_RESOURCE_BROWSER(control_point));
    }
    return TRUE;
}

// Callback: a device has been discovered
static void device_proxy_available(GUPnPControlPoint *control_point, GUPnPDeviceProxy *proxy, gpointer user_data) {

    GUPnPDeviceInfo *device_info = GUPNP_DEVICE_INFO(proxy);
    const char *udn = gupnp_device_info_get_udn(device_info);

    (void) control_point;
    (void) user_data;

    const char *device_type = gupnp_device_info_get_device_type(device_info);
    PRINT("\nDevice type: %s\n", device_type);

    if (strstr(device_type, "Light") || strstr(device_type, "light")) {
        char *device_name = gupnp_device_info_get_friendly_name(device_info);
        PRINT("\tFriendly name: %s\n", device_name);
        PRINT("\tUdn: %s\n", udn);

        // Add light virtual device
        // Note: UPnP udn starts with 'uuid:' (uuid starts on the 6th char)
        PRINT("Adding %s, %s to bridge... ", udn + 5, device_name);
        app_mutex_lock(app_sync_lock);
        size_t vd_index = oc_bridge_add_virtual_device((uint8_t*) udn + 5, strlen(udn) - 5, "upnp", "/oic/d",
                "oic.d.light", device_name, "ocf.2.0.0", "ocf.res.1.0.0,ocf.sh.1.0.0", NULL, NULL);
        app_mutex_unlock(app_sync_lock);
        PRINT("Virtual device index: %d\n", vd_index);

        g_free(device_name);

        // Get service list from control point
        const GList *service_list = gupnp_control_point_list_service_proxies(control_point);
        while (service_list) {
            GUPnPServiceProxy *service_proxy = GUPNP_SERVICE_PROXY(service_list->data);
            GUPnPServiceInfo *service_info = GUPNP_SERVICE_INFO(service_proxy);

            const char *service_udn = gupnp_service_info_get_udn(service_info);
            if (strncmp(udn, service_udn, strlen(udn)) == 0) {
                const char *service_type = gupnp_service_info_get_service_type(service_info);

                PRINT("\tService type: %s\n", service_type);
                PRINT("\tService udn: %s\n", service_udn);

                if (strstr(service_type, "Switch") || strstr(service_type, "switch")) {
                    // Add switch resource
                    register_binary_switch_resource(udn, "/bridge/light/switch", vd_index, service_proxy);
                    gupnp_service_proxy_set_subscribed(service_proxy, true);
                    // TODO: IDD could be added here

                } else if (strstr(service_type, "Dimming") || strstr(service_type, "dimming")) {
                    // Add dimming resource
                    register_light_dimming_resource(udn, "/bridge/light/dimming", vd_index, service_proxy);
                    gupnp_service_proxy_set_subscribed(service_proxy, true);
                    // TODO: IDD could be added here

                } else {
                    // ignore
                }
            }

            service_list = g_list_next(service_list);
        }
    }
}

// Callback: a service has been discovered
static void service_proxy_available(GUPnPControlPoint *control_point, GUPnPServiceProxy *proxy, gpointer user_data) {

    GUPnPServiceInfo *service_info = GUPNP_SERVICE_INFO(proxy);
    const char *udn = gupnp_service_info_get_udn(service_info);

    (void) control_point;
    (void) user_data;

    const char *service_type = gupnp_service_info_get_service_type(service_info);
    PRINT("\nService type: %s\n", service_type);

    // See if virtual device exists for this uuid
    // Note: UPnP udn starts with 'uuid:' (uuid starts on the 6th char)
    app_mutex_lock(app_sync_lock);
    size_t vd_index = oc_bridge_get_virtual_device_index((uint8_t*) udn + 5, strlen(udn) - 5, "upnp");
    app_mutex_unlock(app_sync_lock);

    if (vd_index > 0) {
        PRINT("\tUdn: %s\n", udn);
        PRINT("\tVirtual device index: %d\n", vd_index);
        if (strstr(service_type, "Switch") || strstr(service_type, "switch")) {
            // Add switch resource
            register_binary_switch_resource(udn, "/bridge/light/switch", vd_index, proxy);
            gupnp_service_proxy_set_subscribed(proxy, true);
            // TODO: IDD could be added here

        } else if (strstr(service_type, "Dimming") || strstr(service_type, "dimming")) {
            // Add dimming resource
            register_light_dimming_resource(udn, "/bridge/light/dimming", vd_index, proxy);
            gupnp_service_proxy_set_subscribed(proxy, true);
            // TODO: IDD could be added here

        } else {
            // ignore
        }
    }
}

// Callback: a previously discovered device is no longer available
static void device_proxy_unavailable(GUPnPControlPoint *control_point, GUPnPDeviceProxy *proxy, gpointer user_data) {

    GUPnPDeviceInfo *device_info = GUPNP_DEVICE_INFO(proxy);
    const char *udn = gupnp_device_info_get_udn(device_info);

    (void) control_point;
    (void) user_data;

    // See if virtual device exists for this uuid
    // Note: UPnP udn starts with 'uuid:' (uuid starts on the 6th char)
    app_mutex_lock(app_sync_lock);
    size_t vd_index = oc_bridge_get_virtual_device_index((uint8_t*) udn + 5, strlen(udn) - 5, "upnp");
    app_mutex_unlock(app_sync_lock);

    if (vd_index > 0) {
        char *device_name = gupnp_device_info_get_friendly_name(device_info);
        if (oc_bridge_remove_virtual_device(vd_index) == 0) {
            PRINT("\nRemoved virtual device: %d, %s, %s\n", vd_index, udn + 5, device_name);
        } else {
            PRINT("\nFailed to remove virtual device: %d, %s, %s\n", vd_index, udn + 5, device_name);
        }
        g_free(device_name);
    }
}

// Callback: a previously discovered service is no longer available
static void service_proxy_unavailable(GUPnPControlPoint *control_point, GUPnPServiceProxy *proxy, gpointer user_data) {

    GUPnPServiceInfo *service_info = GUPNP_SERVICE_INFO(proxy);
    const char *udn = gupnp_service_info_get_udn(service_info);

    (void) control_point;
    (void) user_data;

    // Lookup resource, if it exists remove resource
    gpointer resource = g_hash_table_lookup(s_resource_lookup, proxy);
    if (resource) {
        const char *service_type = gupnp_service_info_get_service_type(service_info);
        PRINT("\nRemoved %s, %s\n", udn, service_type);
        remove_resource((oc_resource_t*) resource);
        g_hash_table_remove(s_resource_lookup, proxy);
    }
}

static int app_init(void) {
    int ret = oc_init_platform("Desktop PC", NULL, NULL);
    ret |= oc_bridge_add_bridge_device("UPnP Bridge", "ocf.2.0.0", "ocf.res.1.0.0,ocf.sh.1.0.0", NULL, NULL);
    return ret;
}

static void register_resources(void) {
}

static void signal_event_loop(void) {
#if defined(_WIN32)
    WakeConditionVariable(&cv);
#elif defined(__linux__)
    app_mutex_lock(mutex);
    pthread_cond_signal(&cv);
    app_mutex_unlock(mutex);
#endif
}

void handle_signal(int signal) {
    (void) signal;
    if (s_main_loop) {
        g_main_loop_quit(s_main_loop);
    }
    signal_event_loop();
    quit = 1;
}

#if defined(_WIN32)
DWORD WINAPI ocf_event_thread(LPVOID lpParam) {
    oc_clock_time_t next_event;
    while (quit != 1) {
        app_mutex_lock(app_sync_lock);
        next_event = oc_main_poll();
        app_mutex_unlock(app_sync_lock);

        if (next_event == 0) {
            SleepConditionVariableCS(&cv, &cs, INFINITE);
        } else {
            oc_clock_time_t now = oc_clock_time();
            if (now < next_event) {
                SleepConditionVariableCS(
                        &cv, &cs, (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
            }
        }
    }

    oc_main_shutdown();
    return TRUE;
}
#elif defined(__linux__)
static void *ocf_event_thread(void *data) {
    (void) data;
    oc_clock_time_t next_event;
    while (quit != 1) {
        app_mutex_lock(app_sync_lock);
        next_event = oc_main_poll();
        app_mutex_unlock(app_sync_lock);

        app_mutex_lock(mutex);
        if (next_event == 0) {
            pthread_cond_wait(&cv, &mutex);
        } else {
            ts.tv_sec = (next_event / OC_CLOCK_SECOND);
            ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
            pthread_cond_timedwait(&cv, &mutex, &ts);
        }

        app_mutex_unlock(mutex);
    }
    oc_main_shutdown();
    return NULL;
}
#endif

static void display_menu(void) {
    PRINT("\n\n");
    PRINT("################################################\n");
    PRINT("UPnP Bridge\n");
    PRINT("################################################\n");
    PRINT("[0] Display this menu\n");
    PRINT("-----------------------------------------------\n");
    PRINT("[1] Discover devices\n");
    PRINT("[2] Display summary\n");
    PRINT("-----------------------------------------------\n");
    PRINT("[99] Exit\n");
    PRINT("################################################\n");
    PRINT("\nSelect option: ");
}

void discover_devices(void) {
    // Create a hash table for resource lookup
    s_resource_lookup = g_hash_table_new(NULL, NULL);

    // Create a control point for all devices and services
    GUPnPContext *context = gupnp_context_new(NULL, NULL, 0, NULL);
    GUPnPControlPoint *control_point_ssdp_all = gupnp_control_point_new(context, "ssdp:all");

    g_signal_connect(control_point_ssdp_all, "device-proxy-available", G_CALLBACK(device_proxy_available), NULL);
    g_signal_connect(control_point_ssdp_all, "service-proxy-available", G_CALLBACK(service_proxy_available), NULL);
    g_signal_connect(control_point_ssdp_all, "device-proxy-unavailable", G_CALLBACK(device_proxy_unavailable), NULL);
    g_signal_connect(control_point_ssdp_all, "service-proxy-unavailable", G_CALLBACK(service_proxy_unavailable), NULL);

    // Tell the Control Point to start searching
    gssdp_resource_browser_set_active(GSSDP_RESOURCE_BROWSER(control_point_ssdp_all), TRUE);

    // Enter the main loop. This will start the search and result in callbacks to proxy_available() and proxy_unavailable() functions
    s_main_loop = g_main_loop_new(NULL, 0);
    g_timeout_add_seconds(2, rescan_callback, control_point_ssdp_all); // rescan every 2 seconds
    PRINT("\nWaiting for Client... Use Control-C to exit\n");
    g_main_loop_run(s_main_loop); // terminated with Control-C

    // Clean up
    g_object_unref(control_point_ssdp_all);
    g_object_unref(context);
    s_main_loop = NULL;
    g_hash_table_unref(s_resource_lookup);
}

void display_summary(void) {
    for (size_t vd_index = 0; vd_index < 100; ++vd_index) {
        oc_virtual_device_t *virtual_device = oc_bridge_get_virtual_device_info(vd_index);
        if (virtual_device) {
            PRINT("\nvd_index: %d\n", virtual_device->index);
            PRINT("econame: %s\n", virtual_device->econame.ptr);
            PRINT("v_id_size: %d\n", virtual_device->v_id_size);
            PRINT("v_id: %s\n", virtual_device->v_id);
        }
    }
}

#define SCANF(...)                                                             \
  do {                                                                         \
    if (scanf(__VA_ARGS__) <= 0) {                                             \
      PRINT("ERROR Invalid input\n");                                          \
      while ((c = getchar()) != EOF && c != '\n')                              \
        ;                                                                      \
      fflush(stdin);                                                           \
    }                                                                          \
  } while (0)

bool directoryFound(const char *path) {
    struct stat info;
    if (stat(path, &info) != 0) {
        return false;
    }
    if (info.st_mode & S_IFDIR) {
        return true;
    }
    return false;
}

int main(void) {
    int init;
#if defined(_WIN32)
    InitializeCriticalSection(&cs);
    InitializeConditionVariable(&cv);
    InitializeCriticalSection(&app_sync_lock);
#elif defined(__linux__)
    struct sigaction sa;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
#endif

    static const oc_handler_t handler = { .init = app_init, .signal_event_loop = signal_event_loop,
            .register_resources = register_resources };

#ifdef OC_STORAGE
    if (!directoryFound("upnp_bridge_creds")) {
        printf("Creating upnp_bridge_creds directory for persistent storage.");
#ifdef WIN32
        CreateDirectory("upnp_bridge_creds", NULL);
#else
        mkdir("upnp_bridge_creds", 0755);
#endif
    }
    oc_storage_config("./upnp_bridge_creds/");
#endif /* OC_STORAGE */

    init = oc_main_init(&handler);
    if (init < 0)
        return init;

#if defined(_WIN32)
    event_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ocf_event_thread,
            NULL, 0, NULL);
    if (NULL == event_thread) {
        return -1;
    }
#elif defined(__linux__)
    if (pthread_create(&event_thread, NULL, &ocf_event_thread, NULL) != 0) {
        return -1;
    }
#endif

    int c;
    while (quit != 1) {
        display_menu();
        SCANF("%d", &c);
        switch (c) {
        case 0:
            continue;
            break;
        case 1:
            discover_devices();
            break;
        case 2:
            display_summary();
            break;
        case 99:
            signal_event_loop();
            quit = 1;
            break;
        default:
            break;
        }
    }

#if defined(_WIN32)
    WaitForSingleObject(event_thread, INFINITE);
#elif defined(__linux__)
    pthread_join(event_thread, NULL);
#endif
    return 0;
}

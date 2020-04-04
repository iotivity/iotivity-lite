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

#include <gupnp-context-manager.h>
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

GMainLoop* s_main_loop = NULL;

// Callback: timeout callback to end discovery loop
static gboolean timeout_callback(gpointer user_data) {
	PRINT("End of discovery callback\n");
	(void) user_data;
	g_main_loop_quit(s_main_loop);
	return FALSE;
}

// Callback: a device has been discovered
static void device_proxy_available(GUPnPControlPoint* control_point,
		GUPnPDeviceProxy* proxy, gpointer user_data) {

	GUPnPDeviceInfo* device_info = GUPNP_DEVICE_INFO(proxy);
	const char* udn = gupnp_device_info_get_udn(device_info);

	(void) control_point;
	(void) user_data;

	const char* dev_type = gupnp_device_info_get_device_type(device_info);
	PRINT("\nDevice type: %s\n", dev_type);

	char* dev_name = gupnp_device_info_get_friendly_name(device_info);
	PRINT("\tFriendly name: %s\n", dev_name);

	PRINT("\tUdn: %s\n", udn);

	if (strstr(dev_type, "Light") || strstr(dev_type, "light")) {
		// Add light virtual device
		// Note: UPnP udn starts with 'uuid:' (uuid starts on the 6th char)
		PRINT("Adding %s, %s to bridge... ", udn + 5, dev_name);
		app_mutex_lock(app_sync_lock);
		int vd_index = oc_bridge_add_virtual_device((uint8_t *) udn + 5,
				strlen(udn) - 5, "upnp", "/oic/d", "oic.d.light", dev_name,
				"ocf.2.1.0", "ocf.res.1.3.0,ocf.sh.1.3.0", NULL, NULL);
		app_mutex_unlock(app_sync_lock);
		PRINT("Virtual device index: %d\n", vd_index);
	}

	g_free(dev_name);
}

static int app_init(void) {
	int ret = oc_init_platform("Desktop PC", NULL, NULL);
	ret |= oc_bridge_add_bridge_device("UPnP Bridge", "ocf.2.1.0",
			"ocf.res.1.3.0,ocf.sh.1.3.0", NULL, NULL);
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
	signal_event_loop();
	quit = 1;
}

#if defined(_WIN32)
DWORD WINAPI
ocf_event_thread(LPVOID lpParam)
{
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
static void *
ocf_event_thread(void *data) {
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
			ts.tv_nsec = (next_event % OC_CLOCK_SECOND)
					* 1.e09/ OC_CLOCK_SECOND;
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

void discover_devices() {

	// Create a control point for root devices
	GUPnPContext* context = gupnp_context_new(NULL, NULL, 0, NULL);
//	PRINT("Created context %p\n", context);
	GUPnPControlPoint* control_point_root = gupnp_control_point_new(context,
			"upnp:rootdevice");
//	PRINT("Created control point root %p\n", control_point_root);

	g_signal_connect(control_point_root, "device-proxy-available",
			G_CALLBACK(device_proxy_available), NULL);

	// Tell the Control Point to start searching
	gssdp_resource_browser_set_active(
			GSSDP_RESOURCE_BROWSER(control_point_root), TRUE);

	// Enter the main loop. This will start the search and result in callbacks to device_proxy_available.
	s_main_loop = g_main_loop_new(NULL, 0);
	g_timeout_add_seconds(5, timeout_callback, s_main_loop);
	g_main_loop_run(s_main_loop); // terminated in timeout_callback

	// Clean up
	g_object_unref(control_point_root);
	g_object_unref(context);
	s_main_loop = NULL;
}

void display_summary(void) {
	for (size_t vd_index = 0; vd_index < 100; ++vd_index) {
		oc_virtual_device_t* virtual_device = oc_bridge_get_virtual_device_info(
				vd_index);
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
      fflush(stdin);                                                           \
    }                                                                          \
  } while (0)

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

	static const oc_handler_t handler = { .init = app_init, .signal_event_loop =
			signal_event_loop, .register_resources = register_resources };

#ifdef OC_STORAGE
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
			handle_signal(0);
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

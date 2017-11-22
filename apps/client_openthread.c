#include <openthread/cli.h>
#include <openthread/diag.h>
#include <openthread/openthread.h>
#include <openthread/platform/platform.h>

#include "oc_api.h"
#include "oc_assert.h"
#include "oc_instance.h"

otInstance *ot_instance;

static bool got_discovery_response = false;

static int
app_init(void)
{
  int ret = oc_init_platform("Linux", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.phone", "Mobile Device", "1.0", "1.0",
                       NULL, NULL);
  return ret;
}

#define MAX_URI_LENGTH (30)
static char light_1[MAX_URI_LENGTH];
static oc_endpoint_t *light_server;
static bool light_state = false;

static oc_event_callback_retval_t
stop_observe(void *data)
{
  (void)data;
  PRINT("Stopping OBSERVE\n");
  oc_stop_observe(light_1, light_server);
  return DONE;
}

static void
post_light(oc_client_response_t *data)
{
  PRINT("POST_light:\n");
  if (data->code == OC_STATUS_CHANGED)
    PRINT("POST response OK\n");
  else
    PRINT("POST response code %d\n", data->code);
}

static void
observe_light(oc_client_response_t *data)
{
  PRINT("OBSERVE_light:\n");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    PRINT("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case BOOL:
      PRINT("%d\n", rep->value.boolean);
      light_state = rep->value.boolean;
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (oc_init_post(light_1, light_server, NULL, &post_light, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, !light_state);
    oc_rep_end_root_object();
    if (oc_do_post())
      PRINT("Sent POST request\n");
    else
      PRINT("Could not send POST\n");
  } else
    PRINT("Could not init POST\n");
}

static oc_discovery_flags_t
discovery(const char *anchor, const char *uri, oc_string_array_t types,
          oc_interface_mask_t interfaces, oc_endpoint_t *endpoint,
          void *user_data)
{
  (void)anchor;
  (void)interfaces;
  (void)user_data;
  size_t i;
  int uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;

  for (i = 0; i < oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 11 && strncmp(t, "oic.r.light", 11) == 0) {
      light_server = endpoint;

      strncpy(light_1, uri, uri_len);
      light_1[uri_len] = '\0';

      oc_do_observe(light_1, light_server, NULL, &observe_light, LOW_QOS, NULL);
      oc_set_delayed_callback(NULL, &stop_observe, 10);

      got_discovery_response = true;

      return OC_STOP_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

static void
ot_state_changed(uint32_t flags, void *context)
{
  (void)context;

  if ((flags & OT_CHANGED_THREAD_ROLE) &&
    otThreadGetDeviceRole(ot_instance) >= OT_DEVICE_ROLE_CHILD &&
    !got_discovery_response) {
    oc_do_ip_discovery("oic.r.light", &discovery, NULL);
  }
}

static void
signal_event_loop(void)
{
  ocInstanceSignal();
}

static
int start_thread(void)
{
  if (otLinkSetPanId(ot_instance, 0xface) != OT_ERROR_NONE) {
    OC_ERR("Can't set panid\n");
    return -1;
  }

  if (!otThreadGetAutoStart(ot_instance)) {
    if (otIp6SetEnabled(ot_instance, true) != OT_ERROR_NONE) {
      OC_ERR("Can't enable ip6\n");
      return -1;
    }

    if (otThreadSetEnabled(ot_instance, true) != OT_ERROR_NONE) {
      OC_ERR("Can't enable thread\n");
      return -1;
    }

    if(otThreadSetAutoStart(ot_instance, true) != OT_ERROR_NONE) {
      OC_ERR("Can't set thread autostart\n");
      return -1;
    }
  }
  return 0;
}

int
main(int argc, char *argv[])
{
  // init openthread

  PlatformInit(argc, argv);

  ot_instance = otInstanceInitSingle();

  oc_assert(ot_instance);

  oc_assert(start_thread() == 0);

  otSetStateChangedCallback(ot_instance, ot_state_changed, NULL);

  // init iotivity

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop };

  ocInstanceInit(&handler);

  while (1) {
    // handle openthread
    otTaskletsProcess(ot_instance);
    PlatformProcessDrivers(ot_instance);
  }

  return 0;
}

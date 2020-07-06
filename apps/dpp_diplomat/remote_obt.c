/**
 * OCF onboarding tool that can be remotely invoked by an authorized device.
 */

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_obt.h"
#include "port/oc_clock.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

/* Threading variables */
static pthread_t event_thread;
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;

/* Logic variables */
static int quit;

static int
app_init(void)
{
  int ret = oc_init_platform("OCF", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.dots", "OBT", "ocf.2.0.5",
                       "ocf.res.1.0.0,ocf.sh.1.0.0", NULL, NULL);
  oc_device_bind_resource_type(0, "oic.d.ams");
  oc_device_bind_resource_type(0, "oic.d.cms");
  return ret;
}

/* TODO: Implement onboarding kick-off.
 * Takes UUID to filter on when performing discovery as a parameter of the request
 */
static void
post_obt(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  OC_DBG("POST_OBT:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    OC_DBG("Key: %s \n", oc_string(rep->name));
    switch (rep->type) {
      case OC_REP_STRING:
        OC_DBG("Value: %s \n", oc_string(rep->value.string));
        break;
      default:
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        return;
        break;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
}

/* Main event thread */
static void *
ocf_event_thread(void *data)
{
  (void)data;
  oc_clock_time_t next_event;
  while (quit != 1) {
    next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }
  oc_main_shutdown();
  oc_obt_shutdown();

  return NULL;
}

static void
register_resources(void)
{
  PRINT("Register Resource with local path \"/onboardreq\"\n");
  oc_resource_t *res_onboard = oc_new_resource(NULL, "/onboardreq", 1, 0);
  oc_resource_bind_resource_type(res_onboard, "obt.remote");
  oc_resource_bind_resource_interface(res_onboard, OC_IF_RW);
  oc_resource_set_default_interface(res_onboard, OC_IF_RW);
  oc_resource_set_discoverable(res_onboard, true);
  oc_resource_set_request_handler(res_onboard, OC_POST, post_obt, NULL);
  oc_add_resource(res_onboard);
}

static void
issue_requests(void)
{
  oc_obt_init();
}

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

static void
handle_signal(int signal)
{
  (void)signal;
  quit = 1;
  signal_event_loop();
}

int
main(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int init;

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources = register_resources,
                                        .requests_entry = issue_requests };
#ifdef OC_STORAGE
  oc_storage_config("./remote_onboarding_tool_creds");
#endif /* OC_STORAGE */

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  if (pthread_create(&event_thread, NULL, &ocf_event_thread, NULL) != 0) {
    OC_ERR("Failed to create main OCF event thread\n");
    return -1;
  }

  /* Main interface loop */
  while (quit != 1) {
    // TODO
  }

  // Block for end of main event thread
  pthread_join(event_thread, NULL);

  return 0;
}

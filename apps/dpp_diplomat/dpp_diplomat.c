#include "oc_api.h"
#include "port/oc_clock.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

#define SCANF(...)                                                             \
  do {                                                                         \
    if (scanf(__VA_ARGS__) <= 0) {                                             \
      PRINT("ERROR Invalid input\n");                                          \
      fflush(stdin);                                                           \
    }                                                                          \
  } while (0)

pthread_mutex_t mutex;
pthread_cond_t cv;
static pthread_t event_loop_thread;
struct timespec ts;

int quit = 0;

static int
app_init(void)
{
  int ret = oc_init_platform("Linux", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.phone", "DPP Gateway Diplomat", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

void
handle_signal(int signal)
{
  (void)signal;
  quit = 1;
  signal_event_loop();
}

#define MAX_URI_LENGTH (30)
static char obt[MAX_URI_LENGTH];
static oc_endpoint_t *obt_server;

static oc_discovery_flags_t
discovery(const char *anchor, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
  (void)anchor;
  (void)user_data;
  (void)iface_mask;
  (void)bm;
  int i;
  int uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    // TODO: Update to reflect what OBT resource type consists of
    if (strlen(t) == 10 && strncmp(t, "obt.remote", 10) == 0) {
      oc_endpoint_list_copy(&obt_server, endpoint);
      strncpy(obt, uri, uri_len);
      obt[uri_len] = '\0';

      PRINT("Resource %s hosted at endpoints:\n", obt);
      oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        PRINTipaddr(*ep);
        PRINT("\n");
        ep = ep->next;
      }

      // oc_do_get(a_light, light_server, NULL, &get_light, LOW_QOS, NULL);

      return OC_STOP_DISCOVERY;
    }
  }
  oc_free_server_endpoints(endpoint);
  return OC_CONTINUE_DISCOVERY;
}

static void
issue_requests(void)
{
  PRINT("Discovering remote onboarding tool\n");
  oc_do_ip_discovery("obt.remote", &discovery, NULL);
}

static void
*ocf_event_thread(void *data)
{
  (void)data;
  oc_clock_time_t next_event;
  while (quit != 1) {
    next_event = oc_main_poll();

    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    }
    else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }
  return NULL;
}


int
main(void)
{
  int init;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .requests_entry = issue_requests };

#ifdef OC_STORAGE
  oc_storage_config("./simpleclient_creds");
#endif /* OC_STORAGE */

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  if (pthread_create(&event_loop_thread, NULL, &ocf_event_thread, NULL) != 0) {
    return -1;
  }

  int c;
  while (quit != 1) {
    // TODO: Basic client interaction/request
    SCANF("%d", &c);
  }

  pthread_join(event_loop_thread, NULL);

  if (obt_server != NULL) {
    oc_free_server_endpoints(obt_server);
  }
  oc_main_shutdown();
  return 0;
}

#include "oc_api.h"
#include "port/oc_clock.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>

#define SCANF(...)                                                             \
  do {                                                                         \
    if (scanf(__VA_ARGS__) <= 0) {                                             \
      PRINT("ERROR Invalid input\n");                                          \
      fflush(stdin);                                                           \
    }                                                                          \
  } while (0)

#define FIFOPATH "/tmp/my_fifo"

pthread_mutex_t mutex;
pthread_cond_t cv;
pthread_mutex_t app_lock;
static pthread_t event_loop_thread;
struct timespec ts;

#define MAX_URI_LENGTH (30)
static char obt[MAX_URI_LENGTH];
static oc_endpoint_t *obt_server;

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
    if (strlen(t) == 10 && strncmp(t, "obt.dpp", 10) == 0) {
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

      return OC_STOP_DISCOVERY;
    }
  }
  oc_free_server_endpoints(endpoint);
  return OC_CONTINUE_DISCOVERY;
}

static void
issue_requests(void)
{
  PRINT("Discovering dpp onboarding tool\n");
  oc_do_ip_discovery("obt.dpp", &discovery, NULL);
}

static void
*ocf_event_thread(void *data)
{
  (void)data;
  oc_clock_time_t next_event;
  while (quit != 1) {
    pthread_mutex_lock(&app_lock);
    next_event = oc_main_poll();
    pthread_mutex_unlock(&app_lock);

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

static void
post_obt(oc_client_response_t *data)
{
  if (data->code == OC_STATUS_CHANGED)
    PRINT("POST response: CHANGED\n");
  else if (data->code == OC_STATUS_NOT_MODIFIED)
    PRINT("POST response: NOT MODIFIED\n");
  else if (data->code == OC_STATUS_UNAUTHORIZED)
    PRINT("POST response: UNAUTHORIZED\n");
  else
    PRINT("POST response code %d\n", data->code);
}

static void
get_uuid_input(void)
{
  if (obt_server == NULL) {
    PRINT("No dpp onboarding tool discovered\n");
    return;
  }
  char uuid_input[OC_UUID_LEN];
  PRINT("Enter UUID for device to onboard:");
  SCANF("%36s", uuid_input);
  PRINT("Attempting to POST onboarding request for device %s\n", uuid_input);

  if (oc_init_post(obt, obt_server, NULL, &post_obt, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, uuid, uuid_input);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      PRINT("Sent POST request for onboarding\n");
    }
    else {
      PRINT("Failed to send POST request for onboarding\n");
    }
  }
  else {
    PRINT("Failed to initialize POST request for onboarding\n");
  }
}

static void
poll_for_uuid(void)
{
  if (obt_server == NULL) {
    PRINT("No dpp onboarding tool discovered\n");
    return;
  }

  if (mkfifo(FIFOPATH, 0666) != 0) {
    PRINT("Failed to create named pipe for UUID reading. Already in place?\n");
  }

  PRINT("Polling for UUID from named pipe...\n");

  FILE *uuid_pipe = NULL;
  while (quit != 1) {
    uuid_pipe = fopen(FIFOPATH, "r");
    if (!uuid_pipe) {
      PRINT("Failed to open named pipe for UUID reading\n");
      break;
    }
    char read_buffer[256] = "";
    size_t read_size = fread(read_buffer, 1, 256, uuid_pipe);
    OC_DBG("Read size: %ld\n", read_size);
    if (read_size != 256 && feof(uuid_pipe)) {
      OC_DBG("Reached EOF\n");
    }
    PRINT("String read: %s\n", read_buffer);

    // TODO: Any way to sanitize the input and make sure that UUID is well-formed?
    // POST UUID
    PRINT("Attempting to POST onboarding request for device %s\n", read_buffer);

    if (oc_init_post(obt, obt_server, NULL, &post_obt, LOW_QOS, NULL)) {
      oc_rep_start_root_object();
      oc_rep_set_text_string(root, uuid, read_buffer);
      oc_rep_end_root_object();
      if (oc_do_post()) {
        PRINT("Sent POST request for onboarding\n");
      }
      else {
        PRINT("Failed to send POST request for onboarding\n");
      }
    }
    else {
      PRINT("Failed to initialize POST request for onboarding\n");
    }

    if (uuid_pipe && fclose(uuid_pipe) != 0) {
      PRINT("Failed to close UUID pipe\n");
    }
    uuid_pipe = NULL;
  }
}

static void
display_menu(void)
{
  PRINT("Simple DPP Diplomat\n");
  PRINT("[0] Enter UUID for onboarding\n");
  PRINT("[1] Discover OBT\n");
  PRINT("[2] Poll for UUID From Pipe\n");
  PRINT("[99] Exit\n");
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
  oc_storage_config("./dpp_diplomat_creds");
#endif /* OC_STORAGE */

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  if (pthread_create(&event_loop_thread, NULL, &ocf_event_thread, NULL) != 0) {
    return -1;
  }

  int c;
  while (quit != 1) {
    display_menu();
    SCANF("%d", &c);

    switch (c) {
      case 0:
        get_uuid_input();
        break;
      case 1:
        pthread_mutex_lock(&app_lock);
        if (obt_server != NULL)
          oc_free_server_endpoints(obt_server);
        oc_do_ip_discovery("obt.dpp", &discovery, NULL);
        pthread_mutex_unlock(&app_lock);
        break;
      case 2:
        poll_for_uuid();
        break;
      case 99:
        handle_signal(0);
        break;
      default:
        break;
    }
  }

  pthread_join(event_loop_thread, NULL);

  if (obt_server != NULL) {
    oc_free_server_endpoints(obt_server);
  }
  oc_main_shutdown();
  return 0;
}

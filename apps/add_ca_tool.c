/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "oc_api.h"
#include "security/oc_cred.h"
#include "security/oc_store.h"
#include "util/oc_mem.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;

int quit = 0;
int power;
oc_string_t name;

static int
app_init(void)
{
  int ret = oc_init_platform("Intel", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  oc_new_string(&name, "John's Light", 12);
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
  signal_event_loop();
  quit = 1;
}

int
main(int argc, char *argv[])
{
  FILE * pFile;
  size_t lSize;
  uint8_t * cert;
  uint8_t i = 1;
  size_t result;
  oc_uuid_t subject;
  int device = 0, init = -1;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);
  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources = NULL };

  if (argc < 2) {
    fputs ("CA path not specified\n", stderr);
    exit (1);
  }

  oc_storage_config("./mfg_server_creds");

  init = oc_main_init(&handler);
  if (init < 0) {
    exit (2);
  }

  while (argv[i] != NULL) {
    pFile = fopen (argv[1] , "rb");
    if (pFile==NULL) {
      fputs ("File error\n", stderr);
      exit (3);
    }
    fseek (pFile, 0, SEEK_END);
    lSize = ftell (pFile);
    rewind (pFile);
    cert = oc_mem_malloc (sizeof(char)*lSize);
    if (cert == NULL) {
      fputs ("Memory error\n", stderr);
      exit (4);
    }
    result = fread (cert, 1, lSize, pFile);
    if (result != lSize) {
      fputs ("Reading error\n", stderr);
      exit (5);
    }
    fclose (pFile);

    oc_gen_uuid(&subject);
    oc_sec_cred_t *credobj = oc_sec_new_cred(&subject, device);
    if (!credobj) {
      OC_ERR("get cred");
      exit (6);
    }
    credobj->credtype = 8;
    credobj->mfgtrustca = cert;
    credobj->mfgtrustcalen = lSize;
    credobj->credid = oc_sec_find_max_credid(device) + 1;
    oc_sec_dump_cred(device);
    oc_mem_free(cert);
    i++;
  }

  oc_main_shutdown();
  return 0;
}

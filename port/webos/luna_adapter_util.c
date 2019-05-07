#include <luna-service2/lunaservice.h>
#include <glib.h>
#include <pbnjson.h>
#include "luna_adapter_util.h"
#include "port/oc_log.h"

typedef struct _CONNECTION_STATUS {
  bool isConnectWired;
  bool isConnectWiFi;
} CONNECTION_STATUS_T;

CONNECTION_STATUS_T gConnectionStates;

#define LS_CONNECTIONMANAGER_GETSTATUS_URI "luna://com.webos.service.connectionmanager/getstatus"
#define MAX_LS_NAME_SIZE 1024
#define MAX_GET_LS_SERVICE_NAME_COUNT 5
static LSHandle *g_pLSHandle = NULL;
static GMainContext *g_loopContext = NULL;
static GMainLoop *g_mainLoop = NULL;
static bool g_isLSRegistering = false;
char *g_lsServiceName = NULL;

pthread_t threadId_monitor;

static bool checkLSRegistered()
{
  if (g_pLSHandle)
  {
    OC_DBG("Luna service is already registered");
    return true;
  }
  else
  {
    OC_DBG("Luna service is not registered");
    return false;
  }
}

static bool createLSServiceName()
{
  FILE *fp = NULL;
  char processNameBuff[MAX_LS_NAME_SIZE];
  char lunaServiceBuff[MAX_LS_NAME_SIZE];
  size_t readSize = 0;
  char *command = NULL;

  command = g_strdup_printf("ps -p %d -f | sed -n '2p' | awk '{print $8}' | cut -d '/' -f2", getpid());

  fp = popen(command, "r");
  if (NULL == fp)
  {
    OC_DBG("Failed to open ls-monitor");
    exit(1);
  }

  readSize = fread((void*)processNameBuff, sizeof(char), MAX_LS_NAME_SIZE - 1, fp);
  OC_DBG("processNameBuff : %s, readSize: %d", processNameBuff, readSize);

  processNameBuff[readSize]='0';
  command = g_strdup_printf("find /usr/share/luna-service2/services.d/ -name \"*.*\" | /usr/bin/xargs grep %s | grep 'Name' | cut -d '=' -f2 | cut -d '*' -f1", g_strndup(processNameBuff, readSize-1));

  OC_DBG("PID : %d", getpid());

  // Get service Name by pid
  fp = popen(command, "r");
  if (NULL == fp)
  {
    OC_DBG("Failed to open ls-monitor");
    exit(1);
  }
  readSize = fread((void*)lunaServiceBuff, sizeof(char), MAX_LS_NAME_SIZE - 1, fp);
  OC_DBG("lunaServiceBuff : %s, readSize: %d", lunaServiceBuff, readSize);
  if (0 == readSize)
  {
    OC_DBG("This process does not have Luna service");
    g_free(command);
    pclose(fp);
    return false;
  }
  lunaServiceBuff[readSize]='0';

  g_lsServiceName = g_strdup_printf("%s-iotivity%d", g_strndup(lunaServiceBuff, readSize-1), getpid());

  pclose( fp);

  return true;
}

static void triggerCreateLSServiceName()
{
  for (int i = 0; i < MAX_GET_LS_SERVICE_NAME_COUNT; i++)
  {
    if (createLSServiceName())
    {
      OC_DBG("Luna service name : %s", g_lsServiceName);
      break;
    }
    sleep(1);
  }
}

static void *startLSMainLoop(gpointer user_data)
{
  OC_DBG("startLSMainLoop");

  LSError lserror;
  LSErrorInit(&lserror);

  g_isLSRegistering = true;
  if (g_lsServiceName == NULL)
  {
    OC_DBG("Failed to create Luna service name");
    return;
  }

  g_loopContext = g_main_context_new();
  g_mainLoop = g_main_loop_new(g_loopContext, FALSE);
  g_main_context_push_thread_default(g_loopContext);

  if (!g_mainLoop)
  {
    OC_DBG("Failed to create main loop");
    return;
  }

  if (!LSRegister(g_lsServiceName, &g_pLSHandle, &lserror))
  {
    OC_DBG("Failed to register LS Handle");
    return;
  }
  if (!LSGmainAttach(g_pLSHandle, g_mainLoop, &lserror))
  {
    OC_DBG("Failed to attach main loop");
    return;
  }

  g_isLSRegistering = false;
  g_main_loop_run(g_mainLoop);

  g_main_context_unref(g_loopContext);
  g_main_loop_unref(g_mainLoop);
}

LSHandle* getLSHandle()
{
  OC_DBG("getLSHandle");
  return g_pLSHandle;
}

/**
 * Get connection status callback.
 */
static bool get_connection_status_cb(LSHandle *sh, LSMessage *message, void *ctx)
{
  OC_DBG("Callback for com.webos.service.connectionmanager/getstatus is invoked...");

  jvalue_ref parsedObj = {0};
  jschema_ref input_schema = jschema_parse(j_cstr_to_buffer("{}"), DOMOPT_NOOPT, NULL);

  if (!input_schema)
    return false;

  JSchemaInfo schemaInfo;
  jschema_info_init(&schemaInfo, input_schema, NULL, NULL);
  parsedObj = jdom_parse(j_cstr_to_buffer(LSMessageGetPayload(message)), DOMOPT_NOOPT, &schemaInfo);
  jschema_release(&input_schema);

  if (jis_null(parsedObj))
    return true;

  const char *payload = jvalue_tostring(parsedObj, input_schema);

  OC_DBG("Paylod: %s", payload);
  jvalue_ref wiredObj={0}, wifiObj ={0}, wiredStateObj={0}, wifiStateObj={0};
  if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("wired"), &wiredObj))
  {
    if (jobject_get_exists(wiredObj, J_CSTR_TO_BUF("state"), &wiredStateObj))
    {
      if (jstring_equal2(wiredStateObj, J_CSTR_TO_BUF("connected")) && !gConnectionStates.isConnectWired)
      {
        gConnectionStates.isConnectWired = true;
        oc_network_interface_event(NETWORK_INTERFACE_UP);
        OC_DBG("Wired LAN is connected...");
      }
      else if (jstring_equal2(wiredStateObj, J_CSTR_TO_BUF("disconnected")) && gConnectionStates.isConnectWired)
      {
        gConnectionStates.isConnectWired = false;
        oc_network_interface_event(NETWORK_INTERFACE_DOWN);
        OC_DBG("Wired LAN is disconnected...");
      }
    }
  }
  if (jobject_get_exists(parsedObj, J_CSTR_TO_BUF("wifi"), &wifiObj))
  {
    if (jobject_get_exists(wifiObj, J_CSTR_TO_BUF("state"), &wifiStateObj))
    {
      if (jstring_equal2(wifiStateObj, J_CSTR_TO_BUF("connected")) && !gConnectionStates.isConnectWiFi)
      {
        gConnectionStates.isConnectWiFi = true;
        oc_network_interface_event(NETWORK_INTERFACE_UP);
        OC_DBG("Wi-Fi is connected...");
      }
      else if (jstring_equal2(wifiStateObj, J_CSTR_TO_BUF("disconnected")) && gConnectionStates.isConnectWiFi)
      {
        gConnectionStates.isConnectWiFi = false;
        oc_network_interface_event(NETWORK_INTERFACE_DOWN);
        OC_DBG("Wi-Fi is disconnected...");
      }
    }
  }
  return true;
}

void networkMonitorHandler()
{
  OC_DBG("networkMonitorHandler");
  LSError lserror;
  LSErrorInit(&lserror);

  if (!getLSHandle())
  {
    OC_DBG("Luna service handle is null");
    exit(1);
  }

  if(!LSCall(getLSHandle(), LS_CONNECTIONMANAGER_GETSTATUS_URI,
                          "{\"subscribe\":true}",
                          get_connection_status_cb, NULL, NULL, &lserror))
  {
    OC_DBG("com.webos.service.connectionmanager/getstatus failed");
    LSErrorPrint(&lserror, stderr);
  }
  else
  {
    OC_DBG("com.webos.service.connectionmanager/getstatus succeeds");
  }
}

bool initializeLS(void)
{
  OC_DBG("initializeLS");

  bool result = false;

  if (checkLSRegistered())
   return true;

  if (g_isLSRegistering)
  {
    OC_DBG("Wait for registering LS service");
    sleep(1);
  }

  triggerCreateLSServiceName();

  result = pthread_create(&threadId_monitor, NULL, startLSMainLoop, (void *)NULL);
  if (result)
  {
    OC_DBG("Failed to create LS thread");
    return result;
  }
  for (int i = 0; i < MAX_GET_LS_SERVICE_NAME_COUNT; i++)
  {
    if (checkLSRegistered())
    {
      result = true;
      break;
    }
    else
    {
      sleep(1);
      result = false;
    }
  }
  return result;
}

void terminateLS()
{
  OC_DBG("terminateLS");
  LSError lserror;
  LSErrorInit(&lserror);

  if (g_pLSHandle)
  {
    OC_DBG("g_pLSHandle is not null");
    if (!LSUnregister(g_pLSHandle, &lserror))
    {
      OC_DBG("Failed to unregister Luna service");
      LSErrorPrint(&lserror, stderr);
      LSErrorFree(&lserror);
    }
    g_pLSHandle = NULL;
  }

  g_main_loop_quit(g_mainLoop);
}

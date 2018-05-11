/*  ----UTILITY FILE ------*/

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#define SSID_MAX                 32
#define MAC_VAL_LEN	           4 
#define DEV_VAL_LEN	           8
#define HOSTENT_INTERNAL_HEADER_SIZE        100

#define EASYSETUP_TAG                        "ST"

static char* domain_name_to_ip(const char * pDNS)
{
    size_t i = 0;
    int retVal = -1;
    int length = HOSTENT_INTERNAL_HEADER_SIZE;
    struct hostent pResult;
    struct hostent* pHost = NULL;
    char* buffer = NULL;
    char * pIP = NULL;
    int nErr;

    if(pDNS == NULL)
    {
        PRINT("[Error] pDNS=%s, nErr=%d", pDNS, nErr);
        return pIP;
    }

    length += strlen(pDNS);
    if( (buffer = (char*)malloc(length)) == NULL )
    {
        PRINT("[Error] buffer is NULL.(memory allocation is failed)");
        return pIP;
    }

    PRINT("pDNS=%s, length=%d", pDNS, length);

    while( (retVal = gethostbyname_r(pDNS, &pResult, buffer, length, &pHost, &nErr)) == ERANGE)
    {   // Not enough memory of buffer.
        retVal = -1;
        free(buffer);
        length += HOSTENT_INTERNAL_HEADER_SIZE;
       PRINT("DNS Server require more memory. re-alloc memory buffer.(length=%d)", length);

        if( (buffer = (char*)malloc(length)) == NULL )
        {
            PRINT( "[Error] buffer is NULL.(memory allocation is failed)");
            return pIP;
        }
    }

    PRINT( "pHost=0x%X, retVal=%d, nErr=%d", pHost, retVal, nErr);

    if (pHost == NULL || retVal != 0)
    {
        PRINT( "~SocketResolveDNS - Could not resolve host");
        free(buffer);
        return pIP;
    }



    while(pHost->h_addr_list[i] != NULL)
    {
        PRINT("SocketResolveDNS - Host: %s = %s",
                                 pHost->h_name, inet_ntoa( *(struct in_addr *) (pHost->h_addr_list[i])));

        if (retVal == 0)
        { //if first valid value: it has highest prio so return it
            pIP = strdup(inet_ntoa( *(struct in_addr *) (pHost->h_addr_list[i])));
            if( pIP == NULL || strcmp(pIP, "10.0.0.1")==0 )
            {
                PRINT("There is Bug in gethostbyname_r() of GNU-libc library.\n\t\t pIP(%s) for Domain(%s).", pIP, pDNS);
                if(pIP)
                {
                    free(pIP);
                    pIP = NULL;
                }
                retVal = -1;
            }
            else
            {
                PRINT( "Found IP & Registered to pIP(%s) for Domain(%s).", pIP, pDNS);
                retVal = 1;
            }
        }

      i++;
    }

    if(pIP == NULL )
    {
        PRINT("Not Found IP. Check your network.");
    }

    free(buffer);
    return pIP;
}


static bool
execute_command(const char *cmd, char *result, int result_len)
{
  char buffer[128];
  FILE *fp = popen(cmd, "r");

  if (!fp) {
    return false;
  }

  int add_len = 0;
  while (!feof(fp)) {
    if (fgets(buffer, 128, fp) != NULL) {
      add_len += strlen(buffer);

      if (add_len < result_len) {
        strcat(result, buffer);
      }
    }
  }

  fclose(fp);
  return true;
}

int getMACAddress(unsigned char* pIdBuf, size_t pIdBufSize, unsigned int* pIdOutLen) 
{
  struct ifreq ifr;
  int sock;
  char chMAC[6] = {0,};
  char result[256];

  /** Turn On Wi-Fi */
  printf("[Easy_Setup] Turn on the AP\n");
  execute_command("sudo nmcli nm wifi on", result, 256);
  printf("[Easy_Setup] result : %s\n", result);
 
  sock=socket(AF_INET,SOCK_DGRAM,0);
  strcpy( ifr.ifr_name, "wlan0" );
  ifr.ifr_addr.sa_family = AF_INET;
  if (ioctl( sock, SIOCGIFHWADDR, &ifr ) !=0 ) {
    return -1;
  }
  memcpy(chMAC, ifr.ifr_hwaddr.sa_data, 6);
  for(int i=0;i<6;i++){
   snprintf((char*)(pIdBuf + (i * 2)),pIdBufSize - (i*2),"%.2x",chMAC[i]);
   }
  *pIdOutLen = strlen((char*)pIdBuf);
  close(sock);
  return 1;
}


void generateSoftAP(char *gEasySetupSoftAPSSID)
{
   char *ssid_mnid = "SAMSUNG";
   char *ssid_sid ="0A1";
   char *device_name="Light";
   unsigned int mac_addr_len = 0;
   unsigned char mac_addr[16] = {0,};
   char device_val[DEV_VAL_LEN + 1] = {0,};

   if(getMACAddress(mac_addr, sizeof(mac_addr), &mac_addr_len) != 1) {
     PRINT("getMacAddress() error");
     return ;
   }else {
     snprintf(device_val, sizeof(device_val), "%s", mac_addr+mac_addr_len - MAC_VAL_LEN);
   }

   PRINT("device_val %s",device_val);
   
   snprintf((char *)gEasySetupSoftAPSSID, sizeof(gEasySetupSoftAPSSID), "%s_%s%s%s%s",
                                                                       device_name, EASYSETUP_TAG,
                                                                       ssid_mnid, ssid_sid,
                                                                       device_val);

   PRINT("[ES App] SOFTAP  %s\n",gEasySetupSoftAPSSID);
}
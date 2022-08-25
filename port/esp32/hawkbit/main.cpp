
#include <hawkbit.h>
#include <hawkbit.hpp>
#include <exception>
#include "esp_mac.h"
#include "esp_idf_version.h"
#include "esp_chip_info.h"
#include "esp_system.h"
#include "oc_swupdate.h"


#define VERSION "1.0.0"

const char * root_ca = "-----BEGIN CERTIFICATE-----\n\
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\n\
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n\
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\n\
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\n\
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n\
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\n\
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\n\
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\n\
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\n\
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\n\
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\n\
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\n\
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\n\
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\n\
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\n\
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\n\
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\n\
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\n\
-----END CERTIFICATE-----\n\
";

std::string url = "https://url";
std::string tenant = "tenant";
std::string device_id = "device_id";
std::string device_token = "device_token";

HawkbitClient update(url, tenant, device_id, device_token, root_ca);

void processUpdate(const Deployment& deployment) {
  if (deployment.chunks().size() != 1) {
    throw std::string("Expect update to have one chunk");
  }

  const Chunk& chunk = deployment.chunks().front();
  if (chunk.artifacts().size() != 1 ) {
    throw std::string("Expect update to have one artifact");
  }

  const Artifact& artifact = chunk.artifacts().front();

  try {
    update.updateOTA(artifact, "download-http");
  }
  catch ( std::exception& e ) {
    // download failed, we can re-try
    OC_WRN("Failed to download new firmware: %s", e.what());
    return;
  }

  // all done
  update.reportComplete(deployment, true);
  OC_DBG("OTA Succeed, Rebooting...");
  esp_restart();
}

static
std::string get_mac_address() {
  uint8_t mac_addr[6] = {0};
  esp_efuse_mac_get_default(mac_addr);
  char mac_str[18] = {0};
  snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
           mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
  return mac_str;
}

static
std::string chip_revision() {
  esp_chip_info_t info;
  esp_chip_info(&info);
  return std::to_string(info.revision);
}

void loop()
{
    OC_DBG("Start loop");

    try {

      OC_DBG("readState");

      Print out;
      State current = update.readState();
      current.dump(out, "Serial");

      switch(current.type())
      {
        case State::NONE:
        {
          OC_DBG("No update pending");
          break;
        }
        case State::REGISTER:
        {
          OC_DBG("Need to register");
          update.updateRegistration(current.registration(), {
            {"mac", get_mac_address()},
            {"app.version", VERSION},
            {"esp", "esp32"},
            {"esp32.chipRevision", chip_revision()},
            {"esp32.sdkVersion", esp_get_idf_version()}
          });
          break;
        }
        case State::UPDATE:
        {
          const Deployment& deployment = current.deployment();
          update.reportProgress(deployment, 1, 2);
          try {
            processUpdate(deployment);
          }
          catch (const std::string& error) {
            update.reportComplete(deployment, false, {error});
          }

          break;
        }
        case State::CANCEL:
        {
          update.reportCancelAccepted(current.stop());
          break;
        }
      }
    }
    catch (int err) {
      OC_ERR("Failed to fetch update information: %d", err);
    }

    OC_DBG("End loop");
}

#include <regex>

int
validate_purl(const char *purl)
{
  /* https://stackoverflow.com/questions/38608116/how-to-check-a-specified-string-is-a-valid-url-or-not-using-c-code/38608262
    uses regex pattern:
    "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,4}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)"
    this gives issues with escape sequences, hence removed the following issues:
    unknown escape sequence: '\/' [-Werror]
    unknown escape sequence: '\/' [-Werror]
    unknown escape sequence: '\.' [-Werror]
    unknown escape sequence: '\+' [-Werror]
    unknown escape sequence: '\.' [-Werror]
    unknown escape sequence: '\+' [-Werror]
  */
  // regex pattern
  std::string pattern = "https?://"
                        "(www.)?[-a-zA-Z0-9@:%._+~#=]{2,256}.[a-z]{2,4}\b([-a-"
                        "zA-Z0-9@:%_+.~#?&//=]*)";
  // Construct regex object
  std::regex url_regex(pattern);

  if (std::regex_match(purl, url_regex)) {
    return 0;
  }
  return -1;
}

int
check_new_version(size_t device, const char *url, const char *version)
{
  if (!url) {
    oc_swupdate_notify_done(device, OC_SWUPDATE_RESULT_INVALID_URL);
    return -1;
  }
  OC_DBG("Package url %s\n", url);
  if (version) {
    OC_DBG("Package version: %s\n", version);
  }
  oc_swupdate_notify_new_version_available(device, "2.0",
                                           OC_SWUPDATE_RESULT_SUCCESS);
  return 0;
}

int
download_update(size_t device, const char *url)
{
  (void)url;
  oc_swupdate_notify_downloaded(device, "2.0", OC_SWUPDATE_RESULT_SUCCESS);
  return 0;
}

int
perform_upgrade(size_t device, const char *url)
{
  (void)url;
  oc_swupdate_notify_upgrading(device, "2.0", oc_clock_time(),
                               OC_SWUPDATE_RESULT_SUCCESS);

  oc_swupdate_notify_done(device, OC_SWUPDATE_RESULT_SUCCESS);
  return 0;
}
#ifdef OC_SECURITY
#include "port/oc_log_internal.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"
#include "sdfat.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#define STORE_PATH_SIZE 20
// SD chip select pin
#if defined(__AVR__) || defined(__SAM3X8E__)
const uint8_t chipSelect = 4;
#elif defined(__SAMD21G18A__)
const uint8_t chipSelect = SDCARD_SS_PIN;
#else
#warning Please update Eth shield chip select
#endif

static char g_store_path[STORE_PATH_SIZE] = { 0 };
static int8_t g_store_path_len = 0;

void
list_dir()
{
  // Initialize at the highest speed supported by the board that is
  // not over 50 MHz. Try a lower speed if SPI errors occur.
  if (!sdfile_open_read(_file_holder, "/", O_RDONLY)) {
    sdfat_errorHalt(_sd_holder, "open root failed");
  }
  // list all files in the card with date and size
  sdfile_ls(_file_holder);
}

int
oc_storage_config(const char *store)
{
  if (store == NULL || store[0] == '\0') {
    return -EINVAL;
  }
  g_store_path_len = strlen(store);
  if (g_store_path_len > STORE_PATH_SIZE) {
    return -ENOENT;
  }
  strncpy(g_store_path, store, g_store_path_len);
  g_store_path[g_store_path_len] = '\0';
  _sd_holder = sdfat_create();
  /* Initialize at the highest speed supported by the board that is
   not over 50 MHz. Try a lower speed if SPI errors occur.*/
  if (!sdfat_begin(_sd_holder, chipSelect)) {
    sdfat_initErrorHalt(_sd_holder);
    return -1;
  }
  OC_WRN("initialization done.");
  if (!sdfat_exists(_sd_holder, g_store_path)) {
    if (!sdfat_mkdir(_sd_holder, g_store_path)) {
      OC_ERR("Error creating sec dir");
    }
  }
  _file_holder = sdfile_create();
  list_dir();
  sdfile_close(_file_holder);
  return 0;
}

bool
oc_storage_path(char *buffer, size_t buffer_size)
{
  if (g_store_path_len == 0) {
    return false;
  }
  if (buffer != NULL) {
    if (buffer_size < (size_t)(g_store_path_len + 1)) {
      return false;
    }
    memcpy(buffer, g_store_path, g_store_path_len);
    buffer[g_store_path_len] = '\0';
  }
  return true;
}

int
oc_storage_reset(void)
{
  return -1;
}

long
oc_storage_write(const char *store, const uint8_t *buf, size_t len)
{
  size_t store_len = strlen(store);
  g_store_path[g_store_path_len] = '/';
  strncpy(g_store_path + g_store_path_len + 1, store, store_len);
  g_store_path[1 + g_store_path_len + store_len] = '\0';
  sdfile_open_write(_file_holder, g_store_path, O_WRONLY | O_CREAT | O_TRUNC);
  if (!sdfile_isOpen(_file_holder)) {
    return -1;
  } else {
    if ((len = sdfile_write(_file_holder, buf, len)) == -1) {
      OC_ERR("Error writing to: %s", g_store_path);
      return -1;
    }
    sdfile_close(_file_holder);
  }
  return len;
}

long
oc_storage_size(const char *store)
{
  return -1;
}

long
oc_storage_read(const char *store, uint8_t *buf, size_t len)
{
  size_t store_len = strlen(store);
  g_store_path[g_store_path_len] = '/';
  strncpy(g_store_path + g_store_path_len + 1, store, store_len);
  g_store_path[1 + g_store_path_len + store_len] = '\0';
  sdfile_open_read(_file_holder, g_store_path, O_RDONLY);
  if (!sdfile_isOpen(_file_holder)) {
    OC_ERR("error opening %s", g_store_path);
    return -1;
  }
  while (sdfile_available(_file_holder)) {
    // TODO: check for overflow of buffer
    if ((len = sdfile_read(_file_holder, buf, len)) == -1) {
      OC_ERR("Error reading from: %s", g_store_path);
    }
  }
  sdfile_close(_file_holder);
  return len;
}
#endif /* OC_SECURITY */

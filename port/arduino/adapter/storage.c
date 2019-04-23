#ifdef OC_SECURITY
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "port/oc_storage.h"
#include "port/oc_log.h"
#include "sdfat.h"
#define STORE_PATH_SIZE 20
// SD chip select pin
#if defined(__AVR__) || defined(__SAM3X8E__)
const uint8_t chipSelect = 4;
#elif defined(__SAMD21G18A__)
const uint8_t chipSelect = SDCARD_SS_PIN;
#else
#warning Please update Eth shield chip select
#endif


static char store_path[STORE_PATH_SIZE];
static int8_t store_path_len;

void list_dir(){
// Initialize at the highest speed supported by the board that is
  // not over 50 MHz. Try a lower speed if SPI errors occur.
  if (!sdfile_open_read(_file_holder,"/", O_RDONLY)) {
    sdfat_errorHalt(_sd_holder, "open root failed");
  }
  // list all files in the card with date and size
  sdfile_ls(_file_holder);
}

int oc_storage_config(const char *store)
{
  store_path_len = strlen(store);
  if (store_path_len > STORE_PATH_SIZE){
    return -ENOENT;
  }
  strncpy(store_path, store, store_path_len);
  store_path[store_path_len] = '\0';
  _sd_holder = sdfat_create();
  /* Initialize at the highest speed supported by the board that is
   not over 50 MHz. Try a lower speed if SPI errors occur.*/
  if (!sdfat_begin(_sd_holder, chipSelect)) {
    sdfat_initErrorHalt(_sd_holder);
    return -1;
  }
  OC_WRN("initialization done.");
  if( !sdfat_exists(_sd_holder, store_path))
  {
    if(!sdfat_mkdir(_sd_holder, store_path) )
    {
      OC_ERR("Error creating sec dir");
    }
  }
  _file_holder = sdfile_create();
  list_dir();
  sdfile_close(_file_holder);
  return 0;
}


long
oc_storage_write(const char *store, uint8_t *buf, size_t len)
{
  size_t store_len = strlen(store);
  store_path[store_path_len] = '/';
  strncpy(store_path + store_path_len + 1, store, store_len);
  store_path[1 + store_path_len + store_len] = '\0';
  sdfile_open_write(_file_holder, store_path, O_WRONLY | O_CREAT | O_TRUNC);
  if(!sdfile_isOpen(_file_holder)) {
    return -1;
  }else {
		if((len  =  sdfile_write(_file_holder, buf, len)) == -1) {
			OC_ERR("Error writing to: %s",store_path );
			return -1;
		}
		sdfile_close(_file_holder);
  }
  return len;
}

long
oc_storage_read(const char *store, uint8_t *buf, size_t len)
{
  size_t store_len = strlen(store);
  store_path[store_path_len] = '/';
  strncpy(store_path + store_path_len + 1, store, store_len);
  store_path[1 + store_path_len + store_len] = '\0';
  sdfile_open_read(_file_holder, store_path,  O_RDONLY);
  if(!sdfile_isOpen(_file_holder)) {
    OC_ERR("error opening %s", store_path);
    return -1;
  }
  while(sdfile_available(_file_holder)){
    if((len  =  sdfile_read(_file_holder, buf, len)) == -1) {
      OC_ERR("Error reading from: %s",store_path );
    }
  }
  sdfile_close(_file_holder);
  return len;
}
#endif /* OC_SECURITY */

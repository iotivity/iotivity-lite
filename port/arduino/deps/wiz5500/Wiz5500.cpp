#include <Arduino.h>
#include "Wiz5500.h"
#include <w5500.h>
#include "oc_log.h"

struct wiz5500 {
    void *w5500_ref;
};
// Use this pointer if u dont need the reimplemted methods
wiz5500_t *wiznet5500 = NULL;

wiz5500_t *wiz5500_create()
{
	 wiz5500_t *wiznet_holder;
	 W5500Class *w5500_ref;
	// allocate the wrapper memory
	 wiznet_holder  = (typeof(wiznet_holder))malloc(sizeof(*wiznet_holder));
	if(wiznet_holder == NULL){
		OC_ERR("Memory allocation failed for w5500");
		return NULL;
	}
#ifdef ETHERNET_DYNAMIC
	w5500_ref    = w5500;
#else
	w5500_ref    = &w5500;
#endif
	wiznet_holder->w5500_ref = w5500_ref;
	return wiznet_holder;
}

void wiz5500_destroy(wiz5500_t *wiznet_holder)
{
	if (wiznet_holder== NULL)
  	return;
    // need to handle release of this resource
    free(wiznet_holder);
}
void wiz5500_getIPAddress(wiz5500_t *wiznet_holder, uint8_t *addr){

	W5500Class *w5500_ref;
  if (wiznet_holder == NULL) {
		OC_ERR("w5500 allocated Memory unreachable!");
	}
  w5500_ref = static_cast<W5500Class *>(wiznet_holder->w5500_ref);
  w5500_ref->getIPAddress(addr);
}

uint16_t wiz5500_getRXReceivedSize(wiz5500_t *wiznet_holder, uint8_t *socketID){

	W5500Class *w5500_ref;
  if (wiznet_holder == NULL) {
		OC_ERR("w5500 allocated Memory unreachable!");
		return 1;
	}
  w5500_ref = static_cast<W5500Class *>(wiznet_holder->w5500_ref);
  return w5500_ref->getRXReceivedSize(*socketID);
}

uint8_t wiz5500_readSnSR(wiz5500_t *wiznet_holder, uint8_t *socketID){

	W5500Class *w5500_ref;
 	if (wiznet_holder == NULL) {
		OC_ERR("w5500 allocated Memory unreachable!");
		return 1;
	}
  w5500_ref = static_cast<W5500Class *>(wiznet_holder->w5500_ref);
  return w5500_ref->readSnSR(*socketID);
}
// return number of byte written to socket Sn DIPR register
uint16_t wiz5500_writeSnDIPR(wiz5500_t *wiznet_holder, uint8_t *socketID, uint8_t *mcast_ipaddr){

	W5500Class *w5500_ref;
  if (wiznet_holder == NULL) {
		OC_ERR("w5500 allocated Memory unreachable!");
		return 1;
	}
  w5500_ref = static_cast<W5500Class *>(wiznet_holder->w5500_ref);
  return w5500_ref->writeSnDIPR(*socketID,(uint8_t *)mcast_ipaddr);
}

// return number of byte written to socket Sn DIPR register
uint16_t wiz5500_writeSnDHAR(wiz5500_t *wiznet_holder, uint8_t *socketID, uint8_t *mcast_mac_addr){
	W5500Class *w5500_ref;
  if (wiznet_holder == NULL) {
		OC_ERR("w5500 allocated Memory unreachable!");
		return 1;
	}
  w5500_ref = static_cast<W5500Class *>(wiznet_holder->w5500_ref);
  return w5500_ref->writeSnDHAR(*socketID, mcast_mac_addr);
}

// return number of byte written to socket Sn DIPR register
void wiz5500_writeSnDPORT(wiz5500_t *wiznet_holder, uint8_t *socketID, uint16_t *mcast_port){
	W5500Class *w5500_ref;
	if (wiznet_holder == NULL) {
		OC_ERR("w5500 allocated Memory unreachable!");
	}
  w5500_ref = static_cast<W5500Class *>(wiznet_holder->w5500_ref);
  w5500_ref->writeSnDPORT(*socketID, *mcast_port);
}

/******************************************************************
*
* Copyright 2018 iThemba LABS All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at

*    http://www.apache.org/licenses/LICENSE-2.0

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
******************************************************************/
#include <stdlib.h>
#include <Arduino.h>
#include "port/oc_clock.h"
#include "port/oc_log.h"
#include "TimeLib.h"

#define SERIAL_TIMEOUT 50   // 50ms wait for client response: may need adjustment
#define TIME_REQUEST  7    // ASCII bell character requests a time sync message
#define DEFAULT_TIME  ((time_t)(1357041600UL))

 void
oc_clock_init(void)
{

  #ifdef SERIAL_TIME
  setSyncProvider(requestSync);  //set function to call when sync required
  #endif
  setTime(DEFAULT_TIME);
}
/*Wont it be better to have a millissecond based system time?*/
oc_clock_time_t
oc_clock_time(void)
{
    oc_clock_time_t time = (oc_clock_time_t)secondNow();
    return time * OC_CLOCK_CONF_TICKS_PER_SECOND;
}

unsigned long
oc_clock_seconds(void)
{
    oc_clock_time_t time = (oc_clock_time_t)secondNow();
    return time;
}

void
oc_clock_wait(oc_clock_time_t t)
{
  oc_clock_time_t interval = (oc_clock_time_t)ceil( t / 1.e09);
  oc_clock_time_t beginWait = (oc_clock_time_t)micros();
  while((micros() - beginWait) <= interval ){
   //nop
  }
}
#ifdef WEB_TIME
#endif

#ifdef SERIAL_TIME
  /* the user program(iotivity client can listen to serial event)
  *  on a separate thread, get thus the pctime convert to systime and send on serial link(T1357041600)
  *  Used ntp from client to form a system time(number of second since 1970) and send to Arduino
  *  Arduino can sync with its own ntp time from init(setup). it should not try that in loop unless
  *  the server code is sleeping or blocked
  *
  */
time_t requestSync() {

  // request for time sync from serial client
  iotivitySerial_write(TIME_REQUEST)
  oc_clock_time_t pctime = 0;
  oc_clock_time_t beginWait = millis();
  while (millis() - beginWait < SERIAL_TIMEOUT) {
    if (iotivitySerial_available()) { // receive response from client?
      if(iotivitySerial_find(TIME_HEADER)) {
        pctime = iotivitySerial_parseInt();
        if( pctime >= DEFAULT_TIME) { // check the integer is a valid time (greater than Jan 1 2013)
          //setTime(pctime);
          return pctime;//setTime(pctime); // let the Sync Arduino clock to the time received on the serial port
        }
      }
    }
    //setTime(pctime);
    return pctime; // nothing on receive buffer
  }
}
#endif

#ifdef RTC_TIME
#endif


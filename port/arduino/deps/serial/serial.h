#ifndef __SERIAL_H__
#define __SERIAL_H__
#include <stdint.h>
#include <stdlib.h>
#include "Arduino.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct _serial {
    void *serial;
}serial_t;

extern serial_t *_serial_holder;// = NULL;

#if defined(__AVR__)
#ifdef __cplusplus
#define PCF(str)  ((PROGMEM const char *)(F(str)))
#else
#define PCF(str)  ((PROGMEM const char *)(PSTR(str)))
#endif
void avr_log(PROGMEM const char *format, ...);
#define AVR_LOG(format, ...) avr_log(PCF(format),##__VA_ARGS__)
#elif defined(__SAMD21G18A__) || defined(__SAM3X8E__)
void arm_log(const char *format, ...);
#define ARM_LOG(format, ...) arm_log(format,##__VA_ARGS__)
#else
#error Architecture or board not supported.
#endif




#ifdef __cplusplus
}
#endif

#endif /* __SERIAL_H__ */
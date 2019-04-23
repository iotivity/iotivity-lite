#include <Arduino.h>
#include <stdarg.h>
#if defined(__SAM3X8E__)
#include <UARTClass.h>
#elif defined(__SAMD21G18A__)
#include "Uart.h"
#endif
#include "serial.h"
#define MAX_LOG_BUFFER_SIZE 80

serial_t *_serial_holder = NULL;

serial_t *serial_create()
{
	serial_t *serial_holder;
#if defined(__AVR__)
  HardwareSerial *serial_ref;
#elif defined(__SAM3X8E__)
  UARTClass *serial_ref;
#else
	Serial_ *serial_ref;
#endif
	serial_holder = (typeof(serial_holder))malloc(sizeof(*serial_holder));

  serial_ref = &Serial; // the serial object is on the global space get a ref
  serial_holder->serial = serial_ref;
  return serial_holder;
}
#if defined(__AVR__)
inline void clean_ref(HardwareSerial *serial_ref)
#elif defined(__SAM3X8E__)
inline void clean_ref(UARTClass  *serial_ref)
#else
inline void clean_ref(Serial_  *serial_ref)
#endif
{
	serial_ref = NULL;
}


void serial_destroy(serial_t *serial_holder)
{
	 if (serial_holder== NULL)
        return;
#if defined(__AVR__)
    clean_ref(static_cast<HardwareSerial *>(serial_holder->serial));
#elif defined(__SAM3X8E__ )
    clean_ref(static_cast<UARTClass *>(serial_holder->serial));
#else
    clean_ref(static_cast<Serial_ *>(serial_holder->serial));
#endif
    free(serial_holder);
}
#if defined(__AVR__)
void avr_log(PROGMEM const char *format, ...) {
	if(_serial_holder == NULL) {
    _serial_holder = serial_create();
  }
  HardwareSerial *serial_ref;

  if (_serial_holder == NULL)
      return;
  serial_ref = static_cast<HardwareSerial *>(_serial_holder->serial);
  do {
		va_list ap;
    va_start(ap, format);
    uint16_t formatLength = strlen_P((PGM_P)format) ; // cast it to PGM_P , which is const char *
    if(formatLength == 0 ) return;
    char print_buffer[MAX_LOG_BUFFER_SIZE];
    vsnprintf_P(print_buffer, sizeof(print_buffer), (const char *)format, ap);
    for (char *p = &print_buffer[0]; *p; p++)
		{
			// emulate cooked mode for newlines
			if (*p == '\n')
			{
				serial_ref->write('\r');
			}
		serial_ref->write(*p);
		}
      	va_end(ap);
	} while (0);
}
#else
void arm_log(const char *format, ...) {
  if(_serial_holder == NULL) {
    _serial_holder = serial_create();
  }
  if (_serial_holder == NULL)
      return;
#if defined(__SAM3X8E__ )
  UARTClass *serial_ref;
  serial_ref = static_cast<UARTClass *>(_serial_holder->serial);
#else
  Serial_ *serial_ref;
  serial_ref = static_cast<Serial_ *>(_serial_holder->serial);
#endif
  va_list ap;
  va_start(ap, format);
  uint16_t formatLength = strlen(format) ; // cast it to PGM_P , which is const char *
  if(formatLength == 0 ) return;
  char print_buffer[MAX_LOG_BUFFER_SIZE];
  vsnprintf(print_buffer, sizeof(print_buffer), (const char *)format, ap);
  //serial_ref->print(print_buffer);
  for (char *p = &print_buffer[0]; *p; p++)
  {
    // emulate cooked mode for newlines
    if (*p == '\n')
    {
      serial_ref->write('\r');
    }
    serial_ref->write(*p);
  }
  va_end(ap);
}
#endif

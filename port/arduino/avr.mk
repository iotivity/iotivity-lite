### BOARD_TAG
### It must be set to the board you are currently using. (i.e uno, mega2560, etc.)
BOARD_TAG    = mega2560

### Variant Frequency
F_CPU	 = 16000000L
### Board Chip
MCU?=at$(BOARD_TAG)

### MCU ARCH
ARCHITECTURE=avr

#MCU VAriant
VARIANT		= mega
### FLASHING_BAUDRATE: todo detect the board tag to select the correct flash rate
AVRDUDE_ARD_BAUDRATE = 115200
### MONITOR_BAUDRATE
### It must be set to Serial baudrate value you are using.
MONITOR_BAUDRATE  = $(AVRDUDE_ARD_BAUDRATE)

### AVR_TOOLS_DIR
### Path to the AVR tools directory such as avr-gcc, avr-g++, etc.
AVR_TOOLS_DIR     = $(ARDUINO_DIR)/hardware/tools/avr
### or on Linux: (remove the one you don't want)

### AVRDUDE
AVRDUDE_ARD_PROGRAMMER = wiring


### If avr-gcc -v is higher than 4.9, activate coloring of the output
ifeq "$(AVR_GCC_VERSION)" "1"
    CXXFLAGS += -fdiagnostics-color
endif

### External Memory Options
## 64 KB of external RAM, starting after internal RAM (ATmega128!),
## used for variables (.data/.bss) and heap (malloc()).
## 64 KB of external RAM, starting after internal RAM (ATmega128!),
## only used for heap (malloc()).

ifeq ($(XMEM),1)
#                         0x2200             0xffff
# -----------------------------------------------
#|				|	<---- |	.data	 | .bss     | ---> |	 |
#|				|	stack |variable|	variable| heap |	 |
#|				|				|				 |		      |      |   |
# -----------------------------------------------
EXTMEMOPTS = -Wl,-Map,MegaXmem.map -Wl,--section-start,.data=0x802200,--defsym=__heap_end=0x80ffff,--defsym=__stack=0x8021ff

#                         0x802200             0x80ffff
# ---------------------------------------------------
#| .data		|	.bss      |       |<---- |   |---> |	 |
#| variable	|	variables |       |stack |   |heap |	 |
#|					|			      |				|			 |	 |     |   |
# ---------------------------------------------------
#EXTMEMOPTS = -Wl,--defsym=__heap_start=0x802200,--defsym=__heap_end=0x80ffff

#                 0x8021ff 0x802200          0x80ffff
# -------------------------------------------
#| .bss		  |      |<---- |  .data |---> |	 |
#| variable	|      |stack |variable|heap |	 |
#|					|      |		  |        |     |   |
# -------------------------------------------
#EXTMEMOPTS = -Wl,-Map,MegaDataXmem.map -Wl,--section-start,.bss=0x800200 -Wl,--section-start,.data=0x802200,--defsym=__heap_end=0x80ffff,--defsym=__heap_start=0x802200

else
	EXTMEMOPTS =
endif

LDFLAGS += $(EXTMEMOPTS)

### MONITOR_PORT
### The port your board is connected to. Using an '*' tries all the ports and finds the right one.
##MONITOR_PORT   = /dev/ttyUSB*
MONITOR_PORT     = /dev/ttyACM*

include $(ARDMK_DIR)/Arduino.mk

### CURRENT_DIR
### Do not touch - used for binaries path
CURRENT_DIR       = $(shell basename $(CURDIR))

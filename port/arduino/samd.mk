### BOARD_TAG
### It must be set to the board you are currently using. (i.e uno, mega2560, etc.)
BOARD_TAG   = mkrzero

### Variant Frequency
F_CPU		= 48000000L
### Board Chip
MCU?=cortex-m0plus

### MCU ARCH
ARCHITECTURE=samd

#MCU VAriant
VARIANT			= mkrzero

### MONITOR_PORT
### The port your board is connected to. Using an '*' tries all the ports and finds the right one.
#MONITOR_PORT   = /dev/ttyUSB*
MONITOR_PORT    = /dev/ttyACM*

# Define Arduino support package installation path where SAM device support has been installed
# Linux
ARDUINO_PACKAGE_DIR := $(HOME)/.arduino15/packages


include $(ARDMK_DIR)/Sam.mk

### CURRENT_DIR
### Do not touch - used for binaries path
CURRENT_DIR       = $(shell basename $(CURDIR))

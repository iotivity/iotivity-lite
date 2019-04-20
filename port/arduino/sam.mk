### BOARD_TAG
### It must be set to the board you are currently using. (i.e uno, mega2560, etc.)
BOARD_TAG   = arduino_due_x

### Variant Frequency
F_CPU		= 84000000L
### Board Chip
MCU?=cortex-m3

### MCU ARCH
ARCHITECTURE = sam

#MCU VAriant
VARIANT	= arduino_due_x


### MONITOR_PORT
### The port your board is connected to. Using an '*' tries all the ports and finds the right one.
#MONITOR_PORT   = /dev/ttyUSB*
MONITOR_PORT      = /dev/ttyACM*

# Define Arduino support package installation path where SAM device support has been installed
# Linux
ARDUINO_PACKAGE_DIR := $(HOME)/.arduino15/packages


include $(ARDMK_DIR)/Sam.mk

### CURRENT_DIR
### Do not touch - used for binaries path
CURRENT_DIR       = $(shell basename $(CURDIR))

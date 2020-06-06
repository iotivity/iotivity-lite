### PROJECT_DIR 
### This is the path to where you have created/cloned your project
PROJECT_DIR       = $(PWD)
### ARDMK_DIR
### Path to the Arduino-Makefile directory.
ARDMK_DIR         = $(PROJECT_DIR)/Arduino-Makefile

### ARDUINO_DIR
### Path to the Arduino application and resources directory.
ARDUINO_DIR       = $(HOME)/arduino-home

### AVRDUDE
AVRDUDE_ARD_PROGRAMMER = wiring

### ARDUINO LIBS
ifeq ($(ARCH),avr)
	ARDUINO_LIBS +=  Wire SPI Time pRNG Ethernet2 SdFat
else 
	ARDUINO_LIBS +=  Wire SPI Time Ethernet2 SdFat 
endif

### CFLAGS_STD
### Set the C standard to be used during compilation.
CFLAGS_STD        = -std=gnu11

### CXXFLAGS_STD
### Set the C++ standard to be used during compilation.
CXXFLAGS_STD      += -std=gnu++11 

### CXXFLAGS
### Flags you might want to set for debugging purpose. Comment to stop.#-pedantic
### from https://stackoverflow.com/questions/35586426/gcc-compiler-warning-flag-for-zero-variadic-macro-arguments
### -Wpedantic: emove warning: ISO C++11 requires at least one argument for the "..." in a variadic macro
### -Wvariadic-macros: warning: anonymous variadic macros were introduced in C++11
CXXFLAGS         += -Wno-attributes -Wno-variadic-macros -Wall -Wextra
### CFLAGS
CFLAGS           += -Wno-attributes -Wno-variadic-macros -Wall -Wextra


### CURRENT_DIR
### Do not touch - used for binaries path
CURRENT_DIR       = $(shell basename $(CURDIR))

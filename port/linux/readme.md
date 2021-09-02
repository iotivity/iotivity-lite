# Linux port

This folder contains the linux implementation of the IoTivity porting layer.
It also contains the makefile to build natively on a linux machine.

## make

Make needs to be exectued in in this folder
The default command is `make`

## default build options

Option and default setting in the Linux Makefile

- DEBUG 0
  
  no extra debug information
  
- IPV4 0
  
  no IPV4 support
  
- TCP 0
  
  no TCP support (needed for CLOUD)

- CLOUD 0
  
  no cloud support, e.g no cloud manager to connect the device to the cloud.

- SWUPDATE 0
  
  no software update support (e.g. oic.r.softwareupdate)

- PKI 1
  
  support for PKI (roles)

- MNT 0
  
  no support for maintenaince (e.g. oic.wk.mnt)

- CREATE 0
  
  no support for the create interface

- V6DNS 0
  
  no DNS support

- DYNAMIC 1
  
  dynamic libary creation
  
- SECURE 1
  
  security enabled
  
- OSCORE 1
  
  oscore payload protection enabled
  
- JAVA 0
  
  not building JAVA (SWIG)
  
- IDD 1
  
  enable API to read introspection file from disk
  
- WKCORE

  enable discovery through IETF /.well-known/core on IETFs multicast ALL COAP NODES
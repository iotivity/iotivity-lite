# Introduction

This folder contains code examples using IoTivity.
The apps are intended to use in pairs, e.g. they are not full fledged applications.

The intention of the examples is to explain certain aspects of the Iotivity stack.

To create an OCF compliant server or client please visit: https://iotivity.org/getting-started

naming convention:

- [filename]**_linux** has code specific for linux OS
- [filename]**_windows** has code specific for windows OS
- [filename]**_zephyr** has code specific for zypher OS
- [filename]**_arduino** has code specific for usage on an Arduino platform
- [filename]**_openthread** has code specific for usage on an openthread based platform

## Example applications

- ### Arduino.cpp:
  Server example application explaining how to use IoTivity on an Arduino.
  e.g. how to use IoTivity code in conjunction with the Arduino main loop.

- ### client_block_linux.c:
  Client and Server example with linux main loop.

- ### client_certification_tests.c:
  Client Certification test example
  - runs on Linux only.
  - uses client_certification_tests_IDD.cbor as introspection data.

- ### client_collections_linux.c:
  Client example with collections.

- ### client_linux.c:
  Client example with Linux main loop.

- ### client_multithread_linux.c:
  Client example on linux implementing multiple threads.

- ### client_openthread.c:
  Client example on openthread.

- ### client_zephyr.c:
  Client example on zypher.

- ### cloud_certification_tests.c:
  Cloud certification example.

- ### cloud_client.c:
  Client example with cloud API.

- ### cloud_proxy.c:
  Cloud proxy example.
  - uses cloud_proxy_IDD.cbor as introspection data.
    works on Windows & Linux.

- ### cloud_server.c:
  Server example with Cloud API.

- ### introspectionclient.c:
  Client example of retrieving introspection device data.

- ### multi_device_client_linux.c:
  Client example on linux talking to multiple devices.

- ### multi_device_server_linux.c:
  Server example on linux, implementing more than 1 device.

- ### secure_mcast_client.c:
  Client example with simple secure multicast.
  Works on Linux only.

- ### secure_mcast_server1.c:
  Server example implementing simple secure multicast.
  Works on Linux only. use in combination with secure_mcast_client.c.

- ### secure_mcast_server2.c:
  Server example implementing simple secure multicast.
  Works on Linux only. use in combination with secure_mcast_client.c.

- ### sensor_interrupt_server_zephyr.c:
  Server example implementing a sensor on zypher, showing how to use interupts.

- ### server_arduino.cpp:
  Server example on Arduino.

- ### server_block_linux.c:
  Client and server example on linux.

- ### server_certification_tests.c:
  Server example for certification tests.
  - runs on Linux only.
  - uses server_certification_tests_IDD.cbor as introspection data.

- ### server_collections_linux.c:
  Server example implementing collections.

- ### server_linux.c:
  Server example on Linux.

- ### server_multithread_linux.c:
  Server example on Linux, multi threaded.

- ### server_openthread.c:
  Server example on openthread.

- ### server_rules.c:
  Server example implementing rules.
  - runs on Linux only.
  - uses server_rules_IDD.cbor as introspection data.

- ### server_zephyr.c:
  Client example on zypher.

- ### simpleclient.c:
  Client example on Linux.

- ### simpleclient_windows.c:
  Client example on windows.

- ### simpleserver.c:
  Server example on Linux.

- ### simpleserver_pki.c:
  Server example implementing PKI using test certificates.
  - runs on Linux only.

- ### simpleserver_windows.c:
  Server example on Windows.

- ### smart_home_server_linux.c:
  Server example on Linux.
  - uses smart_home_server_linux_IDD.cbor as introspection data.

- ### smart_home_server_with_mock_swupdate.cpp:
  Server example implementing a mockup of software update.

- ### smart_lock_linux.c:
  Server example of a smart lock on Linux.
  - includes commandline controller.

- ### temp_sensor_client_linux.c:
  Client example of temperature sensor.

- ### push_configurator_multithread_linux.c:
  PUSH configuration client which configures origin server and target server.

- ### push_originserver_multithread_linux.c:
  PUSH origin server which has pushable Resource.

- ### push_targetserver_multithread_linux.c:
  PUSH target server which receives PUSH update request from PUSH origin server.
  It plays the role of PUSH configurator at the same time.
  - for more detail see [OCF Push Notification](./docs/push.md)

- ### Other files:
  The JSON files are the introspection files in JSON.
  The CBOR files are the introspection files in CBOR.

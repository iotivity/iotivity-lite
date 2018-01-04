Getting Started
---------------

IoTivity-Constrained is an open-source software stack and library that
implements the Open Connectivity Foundation (OCF) standards for the
Internet of Things (IoT).

It was designed to build IoT applications for resource-constrained
hardware and software environments. It targets the wide array of
embedded devices using low-power and low-cost MCUs that will proliferate
the
IoT landscape.

Contents
--------

- `IoTivity-Constrained Architecture`_
- `Project directory structure`_
- `Pull dependencies`_
- `Building sample applications on Linux`_
- `Building sample applications on Zephyr (with QEMU)`_
- `Building sample applications on RIOT OS and Contiki`_
- `Framework configuration`_

IoTivity-Constrained Architecture
---------------------------------

.. image:: IoTivityConstrained-Arch.png
   :scale: 100%
   :alt: IoTivity-Constrained Architecture
   :align: center

Iotivity-Constrained's architecture addresses the following design
goals:

- **Laying down constraints**: This is achieved through build-time
  configuration of a set of parameters that constrain the number of
  serviceable connections and requests, payload sizes, memory pool sizes,
  timeouts etc.  These collectively characterize an acceptable workload
  for an application.

- **Determinism**: All memory is statically allocated, and requests fail
  gracefully whenever a workload exceeds the set constraints.

- **Common core**: IoTivity-Constrained will be employed on diverse
  hardware-software environments.  The architecture is therefore
  decoupled into a cross-platform common core with a set of interfaces
  into implementations of platform-specific code. This decoupling isolates
  all of the OCF standards related functionality from lower-level
  platform/environment specific code, that varies per deployment.

- **Platform abstraction**: These are a collection of interfaces with a
  key set of hooks that elicit a contract from implementations. The core
  framework talks via these interfaces to interact with platform specific
  functionality. Implementations may be built with any choice of embedded
  RTOS, network stack and hardware. Any such implementation then becomes a
  "port".  Ports currently exist for Linux, Zephyr, RIOT OS and Contiki.

- **Lightweight design**: This is achieved through tight coupling
  between stack layers and avoiding modularity unless warranted.

Project directory structure
---------------------------

The IoTivity-Constrained source tree has the following directory
structure:

api/*
  contains the implementations of client/server APIs, the resource model
  and introspection layer, utility and helper functions to encode/decode
  to/from OCF’s data model, module for encoding and interpreting type 4
  UUIDs, and handlers for the discovery, platform and device resources.

messaging/coap/*
  contains a tailored CoAP implementation.

security/*
  contains the handlers for secure core OCF resources.

utils/*
  contains a few primitive building blocks used internally by the core
  framework.

deps/*
  contains external project dependencies.

deps/tinycbor/*
  contains the tinyCBOR project.

deps/tinydtls/*
  contains the tinyDTLS project.

include/*
  contains common (across modules) headers.

include/oc_api.h
  contains client/server APIs.

include/oc_rep.h
  contains helper functions to encode/decode to/from OCF’s
  data model.

include/oc_helpers.h
  contains utility functions for allocating strings and
  arrays from pre-allocated memory pools.

port/\*.h
  outlines the platform abstraction.

port/linux/*
  contains an implementation of a Linux port.

port/zephyr/*
  contains an implementation of a Zephyr port.

port/riot/*
  contains an implementation of a RIOT OS port.

port/contiki/*
  contains an implementation of a Contiki port.

apps/*
  contains sample OCF applications.

Pull Dependencies
-----------------

Run ``git submodule update --init`` from
``<iotivity-constrained-root>/``.

Building sample applications on Linux
-------------------------------------

The entire build is specified in ``port/linux/Makefile``. The output of
the build consists of all sample application binaries that are stored
under ``port/linux``.

Run ``make`` for a release mode build without debug output and security.

Run ``make DEBUG=1`` for debug mode build with debug output and without
security.

Add ``SECURE=1`` to the command-lines above for a complete build
including tinyDTLS and modules that implement secure mode operation.

Building sample applications on Zephyr (with QEMU)
--------------------------------------------------

First set up your Zephyr development environment following the Zephyr
Project's
`Getting Started Guide
<https://www.zephyrproject.org/doc/getting_started/getting_started.html>`_.

Before running ``make``, update ``port/zephyr/src/Makefile`` to include
your choice of Zephyr sample from ``apps/``.

Run ``source <Zephyr root>/zephyr-env.sh``.

Run ``make pristine && make`` from ``port/zephyr``.

This should result in a complete build of the Zephyr kernel
and subsystems, the IoTivity-Constrained framework, and the sample app.

Clone the net-tools repository from
https://github.com/zephyrproject-rtos/net-tools.

Follow its README to set up a tap interface using ``loop-socat.sh`` and
``loop-slip-tap.sh.``

This exposes a network interface on Linux to communicate with Zephyr’s
IP stack and the sample app.

Run ``make qemu`` from ``port/zephyr``. This runs the chosen sample on
Zephyr in QEMU.

Now run any appropriate Linux client/server sample against the Zephyr
application to view the request/response flow.

Building sample applications on RIOT OS and Contiki
---------------------------------------------------

Please refer to ``port/riot/README`` and ``port/contiki/README`` for
instructions.

Framework configuration
-----------------------

Build-time configuration options for an application are set in the file
named ``config.h``. This needs to be present in one of the include
paths.  Pre-populated configurations for the samples for all targets are
present in ``port/<platform>/config.h``.

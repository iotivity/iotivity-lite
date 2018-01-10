Getting Started
---------------

IoTivity-Constrained is a lightweight implementation of the `Open Connectivity Foundation <https://openconnectivity.org/>`_ (OCF) standards for the Internet of Things (IoT).

It was designed to build secure and interoperable IoT applications in full compliance with the `OCF specifications <https://openconnectivity.org/developer/specifications>`_ with a minimal footprint not exceeding the needs of the specifications. The stack architecture lends itself to be ported rapidly to any chosen hardware/OS environment.

IoT applications may be built for a wide variety of rich and resource-constrained devices across the IoT landscape. As a general guideline, it should be feasible to deploy applications on class 2 constrained devices (>256KB Flash, >50KB RAM), or better.

The project is open-source, and its code is distributed under the commercial-friendly Apache v2 license.

Contents
--------

- `IoTivity-Constrained Architecture`_
- `Project directory structure`_
- `Setup source tree`_
- `Building sample applications on Linux`_
- `Framework configuration`_

IoTivity-Constrained Architecture
---------------------------------

.. image:: IoTivityConstrained-Arch.png
   :scale: 100%
   :alt: IoTivity-Constrained Architecture
   :align: center

IoTivity-Constrained's design presents the following features:

- **OS agnostic core**: This cross-platform core (written in pure C)
  encompasses the APIs, OCF resource model, protocol, security features,
  memory management and event loop. The core interacts
  with lower level platform-specific functionality via a very limited
  collection of abstract interfaces. Such a  decoupling of the common
  OCF standards related functionality from adaptations to any OS/target
  facilitates greater ease of long-term maintenance and evolution of
  the stack through successive releases of the OCF specifications.

- **Platform abstraction**: These are a collection of abstract interfaces
  with a small set of hooks to platform-specific features. These interfaces
  are defined in generic terms and elicit a specific contract from
  implementations. The core calls into these interfaces to interact with
  the underlying OS/platform. The simplicity and boundedness of these
  interface definitions allow them to be rapidly implemented on any chosen
  OS/target. Such an implementation then constitutes a "port". A number of ports
  (adaptations) currently exist for immediate use, and the project will
  continue to expand this set.

- **Support for static OR dynamic allocation of internal structures**:
  On environments with a C library that supports heap allocation functions,
  the stack can be configured at build-time to use dynamic memory allocation
  to operate without any pre-determined set of resource constraints.

  Alternatively, the stack may be configured to statically allocate all
  internal structures by setting a number of build-time parameters that
  constrain the number of serviceable connections and requests,
  payload sizes, memory pool sizes, timeouts etc.  These
  collectively characterize an acceptable workload for an application.

- **Lightweight design and low complexity**: This is achieved through
  the implementation of functionally cohesive modules, and weak coupling
  between stack layers.

- **Simple C APIs**: The APIs are defined so as to closely align to OCF
  specification constructs aiding greater ease of understanding. Application
  code utilizing these APIs are largely cross-platform as a consequence
  of the design, and can be quickly migrated over to a any other target
  environment.

Project directory structure
---------------------------

api/*
  contains the implementations of client/server APIs, the resource model,
  utility and helper functions to encode/decode
  to/from OCF’s data model, module for encoding and interpreting type 4
  UUIDs, base64 strings, OCF endpoints, and handlers for the discovery, platform and device resources.

messaging/coap/*
  contains a tailored CoAP implementation.

security/*
  contains resource handlers that implement the OCF security model.

utils/*
  contains a few primitive building blocks used internally by the core
  framework.

onboarding_tool/*
  contains the sample onboarding tool (OBT).

deps/*
  contains external project dependencies.

deps/tinycbor/*
  contains the tinyCBOR sources.

deps/mbedtls/*
  contains the mbedTLS sources.

patches/*
  contains patches for deps/mbedTLS and need to be applied once.

include/*
  contains all common headers.

include/oc_api.h
  contains client/server APIs.

include/oc_rep.h
  contains helper functions to encode/decode to/from OCF’s
  data model.

include/oc_helpers.h
  contains utility functions for allocating strings and
  arrays either dynamically from the heap or from pre-allocated
  memory pools.

include/oc_obt.h
  contains the collection of APIs for security onboarding
  and provisioning.

port/\*.h
  collectively represents the platform abstraction.

port/<OS>/*
  contains adaptations for each OS.

apps/*
  contains sample OCF applications.

Setup source tree
-----------------

Grab source and dependencies using:

``git clone --recursive https://github.com/iotivity/iotivity-constrained.git``

Apply mbedTLS patches into deps/mbedtls using:

``patch -p1 < ../../patches/mbedtls_ocf_patch_1``

``patch -p1 < ../../patches/mbedtls_iotivity_constrained_patch_2``

Building sample applications on Linux
-------------------------------------

The entire build is specified in ``port/linux/Makefile``. The output of the build consists of all static and dynamic libraries, and sample application binaries which are stored under ``port/linux``.

Run ``make`` for a release mode build without debug output, security support or support for dynamic memory allocation.

Add ``DYNAMIC=1`` to support dynamic memory allocation.

Add ``SECURE=1`` to include the OCF security layer and mbedTLS.

Add ``DEBUG=1`` for a debug mode build with verbose debug output.

Note: The Linux port is the only adaptation layer that is actively maintained as of this writing (Jan 2018). The other ports will be updated imminently. Please watch for further updates on this matter.

Framework configuration
-----------------------

Build-time configuration options for an application are set in ``config.h``. This needs to be present in one of the include paths.

Pre-populated (sample) configurations for the sample applications for all targets are present in ``port/<OS>/config.h``.

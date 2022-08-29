# Usage of Zephyr Port

## Zephyr application setup

The iotivity-lite port for Zephyr currently has to be built as 
[Third-party Library Code](https://docs.zephyrproject.org/latest/develop/application/index.html#third-party-library-code)
of the [Zephyr application](https://docs.zephyrproject.org/latest/develop/application/index.html).

Add the iotivity-lite git repository as a sub-directory (e.g. a git submodule) to the Zephyr application structure:

```
<home>/app
├── iotivity-lite
├── CMakeLists.txt
├── prj.conf
└── src
    └── main.c
```

The `app/CMakeLists.txt` needs to add the `iotivity-lite` as a subdirectory to cross-compile it to Zephyr
(the iotivity-lite CMake will detect that it has the zephyr port has to be used and also does some checks
on the Zephyr configuration, e.g. detect whether the zephyr file system is enabled an can be used for storage).

If needed, the Zephyr application can configure the iotivity-lite build by pre-setting CMake variables that
iotivity-lite uses prior to the `add_subdirectory` command.

Finally, the Zephyr application then links to one of the `*-static` CMake targets from iotivity-lite.

For example:

```
cmake_minimum_required(VERSION 3.10)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(iotivity_lite_app)

target_sources(app PRIVATE src/main.c)

# Configure iotivity-lite build by pre-setting CMake variables
set(BUILD_EXAMPLE_APPLICATIONS OFF CACHE BOOL "Build example applications." FORCE)
set(OC_IDD_API_ENABLED OFF CACHE BOOL "Enable the Introspection Device Data API." FORCE)
set(OC_TCP_ENABLED OFF CACHE BOOL "Enable OCF communications over TCP. Necessary for Cloud communications." FORCE)
set(OC_IPV4_ENABLED ON CACHE BOOL "Enable IPv4 support." FORCE)
#set(OC_DEBUG_ENABLED ON CACHE BOOL "Enable debug messages." FORCE)
set(OC_SECURITY_ENABLED ON CACHE BOOL "Enable security." FORCE)

# Build iotivity-lite sub-project
add_subdirectory(iotivity-lite)

# Link iotivity-lite to application
target_link_libraries(app PUBLIC server-static)
```

## Zephyr project configuration

The iotivity-lite build requires some Zephyr modules and project configuration to be present

### Storage

iotivity-lite can use either the LittleFS file-system module or the raw flash as storage.

Note: During the port update only the LittleFS file-system has been tested. The raw flash storage
just has been taken from the previous port without modification and has not been tested.

The following project configuration snippet sets up the LittleFS file-system module for the application:

```
CONFIG_FLASH=y
CONFIG_FLASH_SHELL=y
CONFIG_FLASH_MAP=y
CONFIG_FLASH_MAP_SHELL=y

CONFIG_FILE_SYSTEM=y
CONFIG_FILE_SYSTEM_LITTLEFS=y
CONFIG_FILE_SYSTEM_SHELL=y
```

### Posix

iotivity-lite requires the posix API with pthread:

```
CONFIG_POSIX_API=y
CONFIG_PTHREAD_IPC=y
# increase pthread count (default 5)
# Needed?
CONFIG_MAX_PTHREAD_COUNT=10
```

### Networking

Currently the networking should be initialized automatically by Zephyr with `CONFIG_NET_CONFIG_AUTO_INIT=y`.
This causes the networking stack to be initialized by Zephyr prior to calling the `main()` function of the
application.

Also the protocols need to be enabled according to the iotivity-lite build configuration: `CONFIG_NET_UDP, CONFIG_NET_ARP, CONFIG_NET_IPV6, CONFIG_NET_IPV4, CONFIG_NET_IPV4_IGMP, CONFIG_NET_DHCPV4`

It is required to increase the number of IPv6 multicast addresses to accommodate the iotivity-lite multicast addresses.

The `ipadapter.c` implementation of the Zephyr port also uses the socket API and  network management events,
which need to be enabled with `CONFIG_NET_SOCKETS`, `CONFIG_NET_MGMT`, and `CONFIG_NET_MGMT_EVENT`.

On the [STM32H747I Discovery Board](https://docs.zephyrproject.org/latest/boards/arm/stm32h747i_disco/doc/index.html)
the port was tested with, the packet buffer sizes needed to be increased as well.

```
CONFIG_NETWORKING=y
CONFIG_NET_IPV6=y
CONFIG_NET_IPV4=y
CONFIG_NET_ARP=y
CONFIG_NET_UDP=y
CONFIG_NET_DHCPV4=y
CONFIG_NET_IPV4_IGMP=y

# Initialize the networking system automatically
CONFIG_NET_CONFIG_SETTINGS=y
CONFIG_NET_CONFIG_AUTO_INIT=y
CONFIG_NET_CONFIG_NEED_IPV4=y

# increase number of ipv6 multicast addresses (default 3).
# iotivity-lite adds 3 (6 is OC_WKCORE is is defined).
CONFIG_NET_IF_MCAST_IPV6_ADDR_COUNT=5

# Increase network packet buffer counts
CONFIG_NET_PKT_RX_COUNT=400
CONFIG_NET_PKT_TX_COUNT=400
CONFIG_NET_BUF_RX_COUNT=600
CONFIG_NET_BUF_TX_COUNT=600

CONFIG_NET_MGMT=y
CONFIG_NET_MGMT_EVENT=y

CONFIG_NET_SOCKETS=y
# Needed?
CONFIG_NET_SOCKETS_POLL_MAX=20
CONFIG_NET_SOCKETPAIR=y
```

## iotivity-lite initialization

With the iotivity-lite library linked and the Zephyr configuration done, the Zephyr application can use the
iotivity-lite stack like on any other platform and drive the iotivity-lite event loop using Zephyr primitives.

For example:

```
#include <logging/log.h>
LOG_MODULE_REGISTER(iotivity_lite_example, LOG_LEVEL_DBG);

#include <zephyr.h>
#include <linker/sections.h>
#include <errno.h>
#include <stdio.h>

#include <net/net_if.h>
#include <net/net_core.h>
#include <net/net_context.h>
#include <net/net_mgmt.h>

#include <fs/fs.h>
#include <fs/littlefs.h>
#include <storage/flash_map.h>

#include <oc_api.h>
#include <oc_config.h>
static struct k_sem block;

FS_LITTLEFS_DECLARE_DEFAULT_CONFIG(storage);
static struct fs_mount_t lfs_storage_mnt = {
    .type = FS_LITTLEFS,
    .fs_data = &storage,
    .storage_dev = (void *)FLASH_AREA_ID(storage),
    .mnt_point = "/lfs",
};

static void
signal_event_loop(void)
{
    k_sem_give(&block);
}

static void
register_resources(void)
{
    // Here custom resources can be created during initialization of iotivity-lite
}

static void
set_device_custom_property(void *data)
{
  (void)data;
  oc_set_custom_device_property(snr, "123456");
}

static int
app_init(void)
{
  int ret = oc_init_platform("Zephyr", NULL, NULL);
  ret |= oc_add_device("/oic/d",
                       "x.com.zephyr.device",
                       "Zephyr Board",
                       "ocf.2.2.5",
                       "ocf.res.1.3.0,ocf.sh.1.3.0",
                       set_device_custom_property, NULL);
  return ret;
}

void main(void)
{
    int rc;
    struct fs_mount_t *mp = &lfs_storage_mnt;
    unsigned int id = (uintptr_t)mp->storage_dev;
    const struct flash_area *pfa;
    struct fs_statvfs sbuf;

    static const oc_handler_t handler = {
        .init = app_init,
        .signal_event_loop = signal_event_loop,
        .register_resources = register_resources
    };

    k_sem_init(&block, 0, 1);

    LOG_INF("Mount LittleFS partition");
    rc = flash_area_open(id, &pfa);
    if (rc < 0) {
        LOG_ERR("FAIL: unable to find flash area %u: %d", id, rc);
        return;
    }
    LOG_INF("Flash area %u at 0x%x on %s for %u bytes",
            id, (unsigned int)pfa->fa_off, pfa->fa_dev_name,
            (unsigned int)pfa->fa_size);
    flash_area_close(pfa);

    rc = fs_mount(mp);
    if (rc < 0) {
        LOG_ERR("FAIL: mount id %" PRIuPTR " at %s: %d",
                (uintptr_t)mp->storage_dev, mp->mnt_point, rc);
        return;
    }
    LOG_INF("%s mount: %d", mp->mnt_point, rc);

    rc = fs_statvfs(mp->mnt_point, &sbuf);
    if (rc < 0) {
        LOG_ERR("FAIL: statvfs: %d", rc);
            goto out;
    }

    LOG_INF("%s: bsize = %lu; frsize = %lu; blocks = %lu ; bfree = %lu",
            mp->mnt_point,
            sbuf.f_bsize, sbuf.f_frsize,
            sbuf.f_blocks, sbuf.f_bfree);

#ifdef OC_STORAGE
    oc_storage_config(lfs_storage_mnt.mnt_point);
#endif
    if (oc_main_init(&handler) < 0) {
        LOG_ERR("iotivity-lite initialization failed!");
        goto out;
    }

    // Run iotivity-lite event loop
    oc_clock_time_t next_event;
    k_timeout_t k_tmo;

    while (true) {
        next_event = oc_main_poll();
        if (next_event == 0)
            next_event = K_FOREVER.ticks;
        else
            next_event -= oc_clock_time();
        k_tmo.ticks = next_event;
        k_sem_take(&block, k_tmo);
    }

    oc_main_shutdown();
out:
    rc = fs_unmount(mp);
    LOG_INF("%s unmount: %d", mp->mnt_point, rc);
}
```

## Build Zephyr application

With this setup, the Zephyr application including the iotivity-lite stack can be built using the
[Zephyr Toolchain](https://docs.zephyrproject.org/latest/develop/application/index.html#building-an-application).

For example using `west`:
```
cd <home>/app
west build -b <board>
```
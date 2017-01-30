/** @file
 *  @brief IP Support Service sample
 */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <misc/byteorder.h>
#include <misc/printk.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <zephyr.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/conn.h>
#include <bluetooth/gatt.h>
#include <bluetooth/hci.h>
#include <bluetooth/uuid.h>

static char def_device_name[20];
static char def_manufacturer_name[20];
static char def_model_number[16];
static uint16_t def_appearance = 0x0000;

#define DEFAULT_DEVICE_NAME "Test IPSP node"
#define DEVICE_NAME_LEN (20)
#define DEFAULT_APPEARANCE 0x0000
#define DEFAULT_MODEL CONFIG_SOC
#define DEFAULT_MANUFACTURER "Manufacturer"

#if !defined(CONFIG_BLUETOOTH_GATT_DYNAMIC_DB)
static ssize_t read_name(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                         void *buf, uint16_t len, uint16_t offset) {
  const char *name = attr->user_data;

  return bt_gatt_attr_read(conn, attr, buf, len, offset, name, strlen(name));
}

static ssize_t read_appearance(struct bt_conn *conn,
                               const struct bt_gatt_attr *attr, void *buf,
                               uint16_t len, uint16_t offset) {
  uint16_t appearance = sys_cpu_to_le16(def_appearance);

  return bt_gatt_attr_read(conn, attr, buf, len, offset, &appearance,
                           sizeof(appearance));
}

static ssize_t read_model(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                          void *buf, uint16_t len, uint16_t offset) {
  const char *value = attr->user_data;

  return bt_gatt_attr_read(conn, attr, buf, len, offset, value, strlen(value));
}

static ssize_t read_manuf(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                          void *buf, uint16_t len, uint16_t offset) {
  const char *value = attr->user_data;

  return bt_gatt_attr_read(conn, attr, buf, len, offset, value, strlen(value));
}
#endif /* CONFIG_BLUETOOTH_GATT_DYNAMIC_DB */

static struct bt_gatt_attr attrs[] = {
#if !defined(CONFIG_BLUETOOTH_GATT_DYNAMIC_DB)
    BT_GATT_PRIMARY_SERVICE(BT_UUID_GAP),
    BT_GATT_CHARACTERISTIC(BT_UUID_GAP_DEVICE_NAME, BT_GATT_CHRC_READ),
    BT_GATT_DESCRIPTOR(BT_UUID_GAP_DEVICE_NAME, BT_GATT_PERM_READ, read_name,
                       NULL, def_device_name),
    BT_GATT_CHARACTERISTIC(BT_UUID_GAP_APPEARANCE, BT_GATT_CHRC_READ),
    BT_GATT_DESCRIPTOR(BT_UUID_GAP_APPEARANCE, BT_GATT_PERM_READ,
                       read_appearance, NULL, NULL),
    /* Device Information Service Declaration */
    BT_GATT_PRIMARY_SERVICE(BT_UUID_DIS),
    BT_GATT_CHARACTERISTIC(BT_UUID_DIS_MODEL_NUMBER, BT_GATT_CHRC_READ),
    BT_GATT_DESCRIPTOR(BT_UUID_DIS_MODEL_NUMBER, BT_GATT_PERM_READ, read_model,
                       NULL, def_model_number),
    BT_GATT_CHARACTERISTIC(BT_UUID_DIS_MANUFACTURER_NAME, BT_GATT_CHRC_READ),
    BT_GATT_DESCRIPTOR(BT_UUID_DIS_MANUFACTURER_NAME, BT_GATT_PERM_READ,
                       read_manuf, NULL, def_manufacturer_name),
#endif /* CONFIG_BLUETOOTH_GATT_DYNAMIC_DB */
    /* IP Support Service Declaration */
    BT_GATT_PRIMARY_SERVICE(BT_UUID_IPSS),
};

static const struct bt_data ad[] = {
    BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
    BT_DATA_BYTES(BT_DATA_UUID16_ALL, 0x20, 0x18),
};

static const struct bt_data sd[] = {
    BT_DATA(BT_DATA_NAME_COMPLETE, def_device_name, 20),
};

static void connected(struct bt_conn *conn, uint8_t err) {
  if (err) {
    printk("Connection failed (err %u)\n", err);
  } else {
    printk("Connected\n");
  }
}

static void disconnected(struct bt_conn *conn, uint8_t reason) {
  printk("Disconnected (reason %u)\n", reason);
}

static struct bt_conn_cb conn_callbacks = {
    .connected = connected, .disconnected = disconnected,
};

void ipss_set_attributes(char *device, char *manufacturer, char *model) {
  if (device) {
    strcpy(def_device_name, device);
  }
  if (manufacturer) {
    strcpy(def_manufacturer_name, manufacturer);
  }
  if (model) {
    strcpy(def_model_number, model);
  }
}
void ipss_init() {
  if (!def_device_name[0]) {
    strcpy(def_device_name, DEFAULT_DEVICE_NAME);
  }
  if (!def_manufacturer_name[0]) {
    strcpy(def_manufacturer_name, DEFAULT_MANUFACTURER);
  }
  if (!def_model_number[0]) {
    strcpy(def_model_number, DEFAULT_MODEL);
  }
  bt_gatt_register(attrs, ARRAY_SIZE(attrs));

  bt_conn_cb_register(&conn_callbacks);
}

int ipss_advertise(void) {
  int err;

  err = bt_le_adv_start(BT_LE_ADV_CONN, ad, ARRAY_SIZE(ad), sd, ARRAY_SIZE(sd));
  if (err) {
    return err;
  }

  return 0;
}

package org.iotivity;

public interface OCObtDeviceStatusHandler {
    public void handler(OCUuidType uuid, int status, Object userData);
}
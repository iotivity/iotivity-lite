package org.iotivity;

public interface OCOwnershipStatusHandler {
    public void handler(OCUuid uuid, long device_index, boolean owned);
}
package org.iotivity;

public interface OCObtDiscoveryHandler {
    public void handler(OCUuidType uuid, OCEndpoint endpoint, Object userData);
}
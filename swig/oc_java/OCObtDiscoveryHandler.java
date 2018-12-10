package org.iotivity;

public interface OCObtDiscoveryHandler {
    public int handler(OCUuidType uuid, OCEndpoint endpoint, Object userData);
}
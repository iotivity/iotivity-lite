package org.iotivity;

public interface OCDiscoveryHandler {
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMask, OCEndpoint endpoint, int resourcePropertiesMask);
}
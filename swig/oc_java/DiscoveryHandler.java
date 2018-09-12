package org.iotivity;

public interface DiscoveryHandler {
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMasks, OCEndpoint endpoint, int resourcePropertiesMask, Object userData);
}
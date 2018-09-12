package org.iotivity;

public interface DiscoveryHandler {
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMask, OCEndpoint endpoint, int resourcePropertiesMask, Object userData);
}
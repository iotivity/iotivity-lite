package org.iotivity;

public interface OCDiscoveryAllHandler {
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMask, OCEndpoint endpoints, int resourcePropertiesMask, boolean more);
}
package org.iotivity.multideviceclient;

import java.util.ArrayList;
import java.util.List;

public class OcfResourceInfo {

    private String anchor;
    private String uri;
    private String[] types;
    private int interfaceMask;
    private int resourcePropertiesMask;
    private List<String> endpoints = new ArrayList<>();

    OcfResourceInfo(String anchor, String uri, String[] types, int interfaceMask, int resourcePropertiesMask) {
        this.anchor = anchor;
        this.uri = uri;
        this.types = types;
        this.interfaceMask = interfaceMask;
        this.resourcePropertiesMask = resourcePropertiesMask;
    }

    public String getAnchor() {
        return anchor;
    }

    public String getUri() {
        return uri;
    }

    public String[] getTypes() {
        return types;
    }

    public int getInterfaceMask() {
        return interfaceMask;
    }

    public int getResourcePropertiesMask() {
        return resourcePropertiesMask;
    }

    public String[] getEndpoints() {
        return endpoints.toArray(new String[0]);
    }

    public void addEndpoint(String endpoint) {
        if (endpoint != null) {
            endpoints.add(endpoint);
        }
    }

    public int hashCode() {
        int result = 17;
        result = 37 * result + anchor.hashCode();
        result = 37 * result + uri.hashCode();
        return result;
    }

    public boolean equals(Object obj) {
        OcfResourceInfo other = (OcfResourceInfo) obj;
        return (anchor.equals(other.anchor) && uri.equals(other.uri));
    }
}

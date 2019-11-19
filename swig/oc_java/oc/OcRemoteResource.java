package org.iotivity.oc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class OcRemoteResource {

    private String anchor;
    private String uri;
    private String[] types;
    private int interfaceMask;
    private int resourcePropertiesMask;
    private List<String> endpoints = Collections.synchronizedList(new ArrayList<String>());

    OcRemoteResource(String anchor, String uri, String[] types, int interfaceMask, int resourcePropertiesMask) {
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

    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        OcRemoteResource other = (OcRemoteResource) obj;
        return (anchor.equals(other.anchor) && uri.equals(other.uri));
    }
}

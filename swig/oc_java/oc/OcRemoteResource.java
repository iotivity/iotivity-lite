package org.iotivity.oc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.iotivity.*;

/**
 * OcRemoteResource is a resource of a discovered device.
 * <p>
 * Remote resources are discovered using the discovery api call.
 * The device discovery api will also discover the resources of the remote device.
 *
 * @see OcUtils#discoverAllDevices
 */
public class OcRemoteResource {

    private String anchor;
    private String uri;
    private String[] types;
    private int interfaceMask;
    private int resourcePropertiesMask;
    private List<OCEndpoint> endpoints = Collections.synchronizedList(new ArrayList<OCEndpoint>());

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

    public OCEndpoint[] getEndpoints() {
        return endpoints.toArray(new OCEndpoint[0]);
    }

    public void addEndpoint(OCEndpoint endpoint) {
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
        if (obj == null) {
            return false;
        }
        OcRemoteResource other = (OcRemoteResource) obj;
        return (anchor.equals(other.anchor) && uri.equals(other.uri));
    }
}

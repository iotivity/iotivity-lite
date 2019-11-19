package org.iotivity.oc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.iotivity.*;

public class OcRemoteDevice {

    private OCUuid di;
    private String name;
    private String piid;
    private String icv;
    private String dmv;
    private List<String> endpoints = Collections.synchronizedList(new ArrayList<String>());
    private List<OcRemoteResource> resources = Collections.synchronizedList(new ArrayList<OcRemoteResource>());

    OcRemoteDevice(OCUuid di, String name, String piid, String icv, String dmv) {
        this.di = di;
        this.name = name;
        this.piid = (piid != null) ? piid : "";
        this.icv = (icv != null) ? icv : "";
        this.dmv = (dmv != null) ? dmv : "";
    }

    public OCUuid getDeviceId() {
        return di;
    }

    public String getName() {
        return name;
    }

    public String getProtocolIndependentId() {
        return piid;
    }

    public String getSpecVersion() {
        return icv;
    }

    public String getDataModelVersion() {
        return dmv;
    }

    public String[] getEndpoints() {
        return endpoints.toArray(new String[0]);
    }

    public void addEndpoint(String endpoint) {
        if (endpoint != null) {
            endpoints.add(endpoint);
        }
    }

    public OcRemoteResource[] getResources() {
        return resources.toArray(new OcRemoteResource[0]);
    }

    public void addResource(OcRemoteResource resource) {
        if (resource != null) {
            resources.add(resource);
        }
    }

    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        OcRemoteDevice other = (OcRemoteDevice) obj;
        return (di.equals(other.di) && name.equals(other.name));
    }
}

package org.iotivity.multideviceclient;

import java.util.ArrayList;
import java.util.List;

import org.iotivity.OCUuid;

public class OcfDeviceInfo {

    private OCUuid uuid;
    private String name;
    private List<String> endpoints = new ArrayList<>();
    private List<OcfResourceInfo> resourceInfos = new ArrayList<>();

    OcfDeviceInfo(OCUuid uuid, String name) {
        this.uuid = uuid;
        this.name = name;
    }

    public OCUuid getUuid() {
        return uuid;
    }

    public String getName() {
        return name;
    }

    public String[] getEndpoints() {
        return endpoints.toArray(new String[0]);
    }

    public void addEndpoint(String endpoint) {
        if (endpoint != null) {
            endpoints.add(endpoint);
        }
    }

    public OcfResourceInfo[] getResourceInfos() {
        return resourceInfos.toArray(new OcfResourceInfo[0]);
    }

    public void addResourceInfo(OcfResourceInfo resourceInfo) {
        if (resourceInfo != null) {
            resourceInfos.add(resourceInfo);
        }
    }

    public int hashCode() {
        int result = 17;
        result = 37 * result + uuid.hashCode();
        result = 37 * result + name.hashCode();
        return result;
    }

    public boolean equals(Object obj) {
        OcfDeviceInfo other = (OcfDeviceInfo) obj;
        return (uuid.equals(other.uuid) && name.equals(other.name));
    }
}

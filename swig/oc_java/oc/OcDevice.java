package org.iotivity.oc;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.iotivity.*;

public class OcDevice {

    private Map<OcResource, OCResource> resourceLookup = new ConcurrentHashMap<>();

    private String uri;
    private String rt;
    private String name;
    private String specVersion;
    private String dataModelVersion;

    private int deviceIndex; // set by platform in addDevice()

    public OcDevice(String uri, String rt, String name, String specVersion, String dataModelVersion) {
        this.uri = (uri != null) ? uri : "";
        this.rt = (rt != null) ? rt : "";
        this.name = (name != null) ? name : "";
        this.specVersion = (specVersion != null) ? specVersion : "";
        this.dataModelVersion = (dataModelVersion != null) ? dataModelVersion : "";
    }

    public String getUri() {
        return uri;
    }

    public String getRt() {
        return rt;
    }

    public String getName() {
        return name;
    }

    public String getSpecVersion() {
        return specVersion;
    }

    public String getDataModelVersion() {
        return dataModelVersion;
    }

    public OCUuid getId() {
        return OCCoreRes.getDeviceId(deviceIndex);
    }

    public void setIntrospectionData(byte[] IDD) {
        OCIntrospection.setIntrospectionData(deviceIndex, IDD);
    }

    public void addResource(OcResource resource) {
        if (resource != null) {
            if (resource instanceof OcCollection) {
                OCMain.addCollection(resource.getNativeResource());
            } else {
                OCMain.addResource(resource.getNativeResource());
            }

            // save the OCResource for future lookup
            resourceLookup.put(resource, resource.getNativeResource());
        }
    }

    public boolean deleteResource(OcResource resource) {
        if (resource != null) {
            resourceLookup.remove(resource);
            if (resource instanceof OcCollection) {
                OCMain.deleteCollection(resource.getNativeResource());
                return true;
            } else {
                return OCMain.deleteResource(resource.getNativeResource());
            }
        }
        return false;
    }

    public void addCollection(OcCollection collection) {
        addResource(collection);
    }

    public boolean deleteCollection(OcCollection collection) {
        return deleteResource(collection);
    }

    public OcResource[] getResources() {
        return resourceLookup.keySet().toArray(new OcResource[0]);
    }

    public OcCollection[] getCollections() {
        List<OcCollection> collections = new ArrayList<>();
        for (OcResource resource : resourceLookup.keySet()) {
            if (resource instanceof OcCollection) {
                OcCollection collection = (OcCollection) resource;
                collections.add(collection);
            }
        }
        return collections.toArray(new OcCollection[0]);
    }

    public void bindResourceType(String rt) {
        OCMain.deviceBindResourceType(deviceIndex, rt);
    }

    int getDeviceIndex() {
        return deviceIndex;
    }

    void setDeviceIndex(int deviceIndex) {
        this.deviceIndex = deviceIndex;
    }
}

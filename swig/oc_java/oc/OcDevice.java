package org.iotivity.oc;

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

    public void addResource(OcResource resource) {
        if (resource != null) {
            OCResource OC_resource = OCMain.newResource(resource.getName(), resource.getUri(),
                    (short)resource.getResourceTypes().length, deviceIndex);
            for (String resourceType : resource.getResourceTypes()) {
                OCMain.resourceBindResourceType(OC_resource, resourceType);
            }
            for (int resourceIfMask : resource.getInterfaceMasks()) {
                OCMain.resourceBindResourceInterface(OC_resource, resourceIfMask);
            }
            OCMain.resourceSetDefaultInterface(OC_resource, resource.getDefaultInterfaceMask());
            OCMain.resourceSetDiscoverable(OC_resource, resource.isDiscoverable());
            OCMain.resourceSetObservable(OC_resource, resource.isObservable());
            OCMain.resourceSetPeriodicObservable(OC_resource, resource.getPeriodicObservable());
            OCMain.resourceSetRequestHandler(OC_resource, OCMethod.OC_GET, resource.getGetRequestHandler());
            OCMain.resourceSetRequestHandler(OC_resource, OCMethod.OC_PUT, resource.getPutRequestHandler());
            OCMain.resourceSetRequestHandler(OC_resource, OCMethod.OC_POST, resource.getPostRequestHandler());
            OCMain.resourceSetRequestHandler(OC_resource, OCMethod.OC_DELETE, resource.getDeleteRequestHandler());
            OCMain.addResource(OC_resource);

            // save the OCResource for future lookup
            resourceLookup.put(resource, OC_resource);

            // tell the resource its native pointer
            resource.setNativeResource(OC_resource);
        }
    }

    void setDeviceIndex(int deviceIndex) {
        this.deviceIndex = deviceIndex;
    }
}

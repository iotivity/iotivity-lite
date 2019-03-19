package org.iotivity.oc;

import org.iotivity.*;

public class OcResource {

    protected String name;
    protected String uri;
    protected String[] resourceTypes;
    protected int[] interfaceMasks; // each entry is an item from
                                    // OCInterfaceMask
    private int defaultInterfaceMask;
    private boolean discoverable;
    private boolean observable;
    private int periodicObservable;
    private OCRequestHandler getRequestHandler;
    private OCRequestHandler putRequestHandler;
    private OCRequestHandler postRequestHandler;
    private OCRequestHandler deleteRequestHandler;

    protected OCResource nativeResource;

    protected OcResource() {
    }

    public OcResource(OcDevice device, String name, String uri, String[] resourceTypes, int[] interfaceMasks) {
        if (device == null) {
            throw new IllegalArgumentException("OcDevice cannot be null");
        }

        this.name = (name != null) ? name : "";
        this.uri = (uri != null) ? uri : "";
        this.resourceTypes = (resourceTypes != null) ? resourceTypes : new String[0];
        this.interfaceMasks = (interfaceMasks != null) ? interfaceMasks : new int[0];

        nativeResource = OCMain.newResource(this.name, this.uri, (short) this.resourceTypes.length,
                device.getDeviceIndex());

        if (nativeResource != null) {
            for (String resourceType : this.resourceTypes) {
                OCMain.resourceBindResourceType(nativeResource, resourceType);
            }
            for (int resourceIfMask : this.interfaceMasks) {
                OCMain.resourceBindResourceInterface(nativeResource, resourceIfMask);
            }
        }
    }

    public String getName() {
        return name;
    }

    public String getUri() {
        return uri;
    }

    public String[] getResourceTypes() {
        return resourceTypes;
    }

    public int[] getInterfaceMasks() {
        return interfaceMasks;
    }

    public int getDefaultInterfaceMask() {
        return defaultInterfaceMask;
    }

    public void setDefaultInterfaceMask(int defaultInterfaceMask) {
        this.defaultInterfaceMask = defaultInterfaceMask;
        OCMain.resourceSetDefaultInterface(nativeResource, this.defaultInterfaceMask);
    }

    public boolean isDiscoverable() {
        return discoverable;
    }

    public void setDiscoverable(boolean discoverable) {
        this.discoverable = discoverable;
        OCMain.resourceSetDiscoverable(nativeResource, this.discoverable);
    }

    public boolean isObservable() {
        return observable;
    }

    public void setObservable(boolean observable) {
        this.observable = observable;
        OCMain.resourceSetObservable(nativeResource, this.observable);
    }

    public int getPeriodicObservable() {
        return periodicObservable;
    }

    public void setPeriodicObservable(int periodicObservable) {
        this.periodicObservable = periodicObservable;
        OCMain.resourceSetPeriodicObservable(nativeResource, this.periodicObservable);
    }

    public OCRequestHandler getGetRequestHandler() {
        return getRequestHandler;
    }

    public void setGetRequestHandler(OCRequestHandler getRequestHandler) {
        if (getRequestHandler != null) {
            OCMain.resourceSetRequestHandler(nativeResource, OCMethod.OC_GET, getRequestHandler);
            this.getRequestHandler = getRequestHandler;
        }
    }

    public OCRequestHandler getPutRequestHandler() {
        return putRequestHandler;
    }

    public void setPutRequestHandler(OCRequestHandler putRequestHandler) {
        if (putRequestHandler != null) {
            OCMain.resourceSetRequestHandler(nativeResource, OCMethod.OC_PUT, putRequestHandler);
            this.putRequestHandler = putRequestHandler;
        }
    }

    public OCRequestHandler getPostRequestHandler() {
        return postRequestHandler;
    }

    public void setPostRequestHandler(OCRequestHandler postRequestHandler) {
        if (postRequestHandler != null) {
            OCMain.resourceSetRequestHandler(nativeResource, OCMethod.OC_POST, postRequestHandler);
            this.postRequestHandler = postRequestHandler;
        }
    }

    public OCRequestHandler getDeleteRequestHandler() {
        return deleteRequestHandler;
    }

    public void setDeleteRequestHandler(OCRequestHandler deleteRequestHandler) {
        if (deleteRequestHandler != null) {
            OCMain.resourceSetRequestHandler(nativeResource, OCMethod.OC_DELETE, deleteRequestHandler);
            this.deleteRequestHandler = deleteRequestHandler;
        }
    }

    public int notifyObservers() {
        return OCMain.notifyObservers(nativeResource);
    }

    OCResource getNativeResource() {
        return nativeResource;
    }
}

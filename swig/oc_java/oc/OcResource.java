package org.iotivity.oc;

import org.iotivity.*;

public class OcResource {

    private String name;
    private String uri;
    private String[] resourceTypes;
    private int[] interfaceMasks; // each entry is one of from OCInterfaceMask
    private int defaultInterfaceMask;
    private boolean discoverable;
    private boolean observable;
    private int periodicObservable;
    private OCRequestHandler getRequestHandler;
    private OCRequestHandler putRequestHandler;
    private OCRequestHandler postRequestHandler;
    private OCRequestHandler deleteRequestHandler;

    private OCResource nativeResource; // set by device in addResource()

    public OcResource(String name, String uri, String[] resourceTypes, int[] interfaceMasks) {
        this.name = (name != null) ? name : "";
        this.uri = (uri != null) ? uri : "";
        this.resourceTypes = (resourceTypes != null) ? resourceTypes : new String[0];
        this.interfaceMasks = (interfaceMasks != null) ? interfaceMasks : new int[0];
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
    }

    public boolean isDiscoverable() {
        return discoverable;
    }

    public void setDiscoverable(boolean discoverable) {
        this.discoverable = discoverable;
    }

    public boolean isObservable() {
        return observable;
    }

    public void setObservable(boolean observable) {
        this.observable = observable;
    }

    public int getPeriodicObservable() {
        return periodicObservable;
    }

    public void setPeriodicObservable(int periodicObservable) {
        this.periodicObservable = periodicObservable;
    }

    public OCRequestHandler getGetRequestHandler() {
        return getRequestHandler;
    }

    public void setGetRequestHandler(OCRequestHandler getRequestHandler) {
        this.getRequestHandler = getRequestHandler;
    }

    public OCRequestHandler getPutRequestHandler() {
        return putRequestHandler;
    }

    public void setPutRequestHandler(OCRequestHandler putRequestHandler) {
        this.putRequestHandler = putRequestHandler;
    }

    public OCRequestHandler getPostRequestHandler() {
        return postRequestHandler;
    }

    public void setPostRequestHandler(OCRequestHandler postRequestHandler) {
        this.postRequestHandler = postRequestHandler;
    }

    public OCRequestHandler getDeleteRequestHandler() {
        return deleteRequestHandler;
    }

    public void setDeleteRequestHandler(OCRequestHandler deleteRequestHandler) {
        this.deleteRequestHandler = deleteRequestHandler;
    }

    void setNativeResource(OCResource nativeResource) {
        this.nativeResource = nativeResource;
    }
}

package org.iotivity.oc;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.iotivity.*;

/**
 * OcDevice is a device of the platform.
 * <p>
 * Devices can only be added to the platform after the platform has been initialized.
 * Devices are typically added to the platform in the platform's initialize handler.
 *
 * @see OcPlatform#platformInit
 * @see OcPlatform#addDevice
 * @see OCMainInitHandler#initialize
 */
public class OcDevice {

    private Map<OcResource, OCResource> resourceLookup = new ConcurrentHashMap<>();

    private String uri;
    private String rt;
    private String name;
    private String specVersion;
    private String dataModelVersion;

    private int deviceIndex; // set by platform in addDevice()

    /**
     * Constructs an OcDevice.
     * <p>
     * @param uri  the uri of the device
     * @param rt  the resource type of the device
     * @param name  the name of the device
     * @param specVersion  the spec version of the device
     * @param dataModelVersion  the data model version of the device
     */
    public OcDevice(String uri, String rt, String name, String specVersion, String dataModelVersion) {
        this.uri = (uri != null) ? uri : "";
        this.rt = (rt != null) ? rt : "";
        this.name = (name != null) ? name : "";
        this.specVersion = (specVersion != null) ? specVersion : "";
        this.dataModelVersion = (dataModelVersion != null) ? dataModelVersion : "";
    }

    /**
     * Returns the uri of this device.
     * <p>
     * @return uri
     */
    public String getUri() {
        return uri;
    }

    /**
     * Returns the resource type of this device.
     * <p>
     * @return resource type
     */
    public String getRt() {
        return rt;
    }

    /**
     * Returns the name of this device.
     * <p>
     * @return name
     */
    public String getName() {
        return name;
    }

    /**
     * Returns the spec version of this device.
     * <p>
     * @return spec version
     */
    public String getSpecVersion() {
        return specVersion;
    }

    /**
     * Returns the data model version of this device.
     * <p>
     * @return data model version
     */
    public String getDataModelVersion() {
        return dataModelVersion;
    }

    /**
     * Returns the id of this device.
     * <p>
     * @return OCUuid
     *
     * @see OCUuid
     */
    public OCUuid getId() {
        return OCCoreRes.getDeviceId(deviceIndex);
    }

    /**
     * Sets the introspection data of to this device.
     * <p>
     * @param idd  the introspection data byte array
     */
    public void setIntrospectionData(byte[] idd) {
        OCIntrospection.setIntrospectionData(deviceIndex, idd);
    }

    /**
     * Sets the immutable device id of to this device.
     * <p>
     * @param piid  the immutable device id
     *
     * @see OCUuid
     */
    public void setImmutableDeviceId(OCUuid piid) {
        OCMain.setImmutableDeviceIdentifier(deviceIndex, piid);
    }

    /**
     * Adds a resource to this device.
     * <p>
     * @param resource  the resource to add
     *
     * @see OcResource
     */
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

    /**
     * Deletes a resource from this device.
     * <p>
     * @param resource  the resource to delete
     * @return true on success, false otherwise
     *
     * @see OcResource
     */
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

    /**
     * Adds a collection to this device.
     * <p>
     * @param collection  the collection to add
     *
     * @see OcCollection
     */
    public void addCollection(OcCollection collection) {
        addResource(collection);
    }

    /**
     * Deletes a collection from this device.
     * <p>
     * @param collection  the collection to delete
     * @return true on success, false otherwise
     *
     * @see OcCollection
     */
    public boolean deleteCollection(OcCollection collection) {
        return deleteResource(collection);
    }

    /**
     * Returns the resources of this device.
     * <p>
     * @return Array of OcResource
     *
     * @see OcResource
     */
    public OcResource[] getResources() {
        return resourceLookup.keySet().toArray(new OcResource[0]);
    }

    /**
     * Returns the collections of this device.
     * <p>
     * @return Array of OcCollection
     *
     * @see OcCollection
     */
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

    /**
     * Binds a resource type to this device.
     * <p>
     * @param rt  the resource type
     */
    public void bindResourceType(String rt) {
        OCMain.deviceBindResourceType(deviceIndex, rt);
    }

    /**
     * Resets this device.
     */
    public void resetDevice() {
        OCMain.resetDevice(deviceIndex);
    }

    /**
     * Initializes connectivity to this device.
     * <p>
     * @return 0 on success, -1 otherwise
     */
    public int initConnectivity() {
        return OCConnectivity.init(deviceIndex);
    }

    /**
     * Ends connectivity to this device.
     */
    public void shutdownConnectivity() {
        OCConnectivity.shutdown(deviceIndex);
    }

    int getDeviceIndex() {
        return deviceIndex;
    }

    void setDeviceIndex(int deviceIndex) {
        this.deviceIndex = deviceIndex;
    }
}

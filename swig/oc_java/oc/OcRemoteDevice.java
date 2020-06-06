package org.iotivity.oc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.iotivity.*;

/**
 * OcRemoteDevice is a device that has been discovered.
 * <p>
 * Remote devices can be discovered using the discovery api call.
 *
 * @see OcUtils#discoverAllDevices
 * @see OcDeviceDiscoveryHandler#discoveredDevice
 */
public class OcRemoteDevice {

    private OCUuid di;
    private String name;
    private String piid;
    private String icv;
    private String dmv;
    private List<OcRemoteResource> resources = Collections.synchronizedList(new ArrayList<OcRemoteResource>());

    OcRemoteDevice(OCUuid di, String name, String piid, String icv, String dmv) {
        if ((di == null) || (name == null)) {
            throw new IllegalArgumentException("di or name cannot be null");
        }
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

    public OcRemoteResource[] getResources() {
        return resources.toArray(new OcRemoteResource[0]);
    }

    public void addResource(OcRemoteResource resource) {
        if (resource != null) {
            resources.add(resource);
        }
    }

    public int hashCode() {
        int result = 17;
        result = 37 * result + di.hashCode();
        result = 37 * result + name.hashCode();
        return result;
    }

    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        OcRemoteDevice other = (OcRemoteDevice) obj;
        return (di.equals(other.di) && name.equals(other.name));
    }
}

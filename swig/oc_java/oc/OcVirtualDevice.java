package org.iotivity.oc;

import org.iotivity.*;

/**
 * OcVirtualDevice is a virtual device of the bridge.
 *
 * @see OcBridge
 * @see OcDevice
 */
public class OcVirtualDevice extends OcDevice {

    private byte[] virtualDeviceId;
    private String ecoSystemName;

    /**
     * Constructs an OcVirtualDevice.
     * <p>
     * @param virtualDeviceId  the virtual device id of the virtual device
     * @param ecoSystemName  the eco system name of the virtual device
     * @param uri  the uri of the virtual device
     * @param rt  the resource type of the virtual device
     * @param name  the name of the virtual device
     * @param specVersion  the spec version of the virtual device
     * @param dataModelVersion  the data model version of the virtual device
     */
    public OcVirtualDevice(byte[] virtualDeviceId, String ecoSystemName, String uri, String rt, String name, String specVersion, String dataModelVersion) {
        this(virtualDeviceId, ecoSystemName, uri, rt, name, specVersion, dataModelVersion, null);
    }

    /**
     * Constructs an OcVirtualDevice.
     * <p>
     * @param virtualDeviceId  the virtual device id of the virtual device
     * @param ecoSystemName  the eco system name of the virtual device
     * @param uri  the uri of the virtual device
     * @param rt  the resource type of the virtual device
     * @param name  the name of the virtual device
     * @param specVersion  the spec version of the virtual device
     * @param dataModelVersion  the data model version of the virtual device
     * @param addDeviceCallback  the callback invoked after the virtual device is added to the bridge
     */
    public OcVirtualDevice(byte[] virtualDeviceId, String ecoSystemName, String uri, String rt, String name, String specVersion, String dataModelVersion, OCAddDeviceHandler addDeviceCallback) {
        super(uri, rt, name, specVersion, dataModelVersion, addDeviceCallback);
        this.virtualDeviceId = virtualDeviceId;
        this.ecoSystemName = ecoSystemName;
    }

    /**
     * Returns the virtual device id of this virtual device.
     * <p>
     *
     * @return virtual device id
     */
    public byte[] getVirtualDeviceId() {
        return virtualDeviceId;
    }

    /**
     * Returns the eco system name of this virtual device.
     * <p>
     *
     * @return eco system name
     */
    public String getEcoSystemName() {
        return ecoSystemName;
    }
}

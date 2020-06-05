package org.iotivity.oc;

import org.iotivity.*;

/**
 * OcBridge is a bridge device.
 * <p>
 * The bridge can only be created after the platform has been initialized.
 * The bridge can be created in the platform's initialize handler.
 *
 * @see OcPlatform#platformInit
 * @see OCMainInitHandler#initialize
 */
public class OcBridge {
    private String name;
    private String specVersion;
    private String dataModelVersion;

    /**
     * Constructs an OcBridge.
     * <p>
     * @param name  the name of the bridge
     * @param specVersion  the spec version of the bridge
     * @param dataModelVersion  the data model version of the bridge
     */
    public OcBridge(String name, String specVersion, String dataModelVersion) {
        this(name, specVersion, dataModelVersion, null);
    }

    /**
     * Constructs an OcBridge.
     * <p>
     * @param name  the name of the bridge
     * @param specVersion  the spec version of the bridge
     * @param dataModelVersion  the data model version of the bridge
     * @param bridgeCallback  the callback invoked after the bridge is created
     */
    public OcBridge(String name, String specVersion, String dataModelVersion, OCAddDeviceHandler bridgeCallback) {
        this.name = (name != null) ? name : "";
        this.specVersion = (specVersion != null) ? specVersion : "";
        this.dataModelVersion = (dataModelVersion != null) ? dataModelVersion : "";
        int ret = OCBridge.addBridgeDevice(this.name, this.specVersion, this.dataModelVersion, bridgeCallback);
        if (ret < 0) {
            System.err.println("Error in OCBridge.addBridgeDevice() in OcBridge.ctor()");
        }
    }

    /**
     * Returns the name of this bridge.
     * <p>
     * @return name
     */
    public String getName() {
        return name;
    }

    /**
     * Returns the spec version of this bridge.
     * <p>
     * @return spec version
     */
    public String getSpecVersion() {
        return specVersion;
    }

    /**
     * Returns the data model version of this bridge.
     * <p>
     * @return data model version
     */
    public String getDataModelVersion() {
        return dataModelVersion;
    }

    /**
     * Adds a virtual device to this bridge.
     * <p>
     * @param virtualDevice  the virtual device to add
     * @return &gt;0 on success, 0 otherwise
     *
     * @see OcVirtualDevice
     */
    public int addVirtualDevice(OcVirtualDevice virtualDevice) {
        int ret = -1;

        if (virtualDevice != null) {

            ret = (int) OCBridge.addVirtualDevice(virtualDevice.getVirtualDeviceId(), virtualDevice.getEcoSystemName(),
                    virtualDevice.getUri(), virtualDevice.getRt(), virtualDevice.getName(),
                    virtualDevice.getSpecVersion(), virtualDevice.getDataModelVersion(), virtualDevice.getAddDeviceCallback());

            if (ret > 0) {
                // tell the device its index
                virtualDevice.setDeviceIndex(ret);
            }
        }

        return ret;
    }

    /**
     * Removes a virtual device from this bridge.
     * <p>
     * Any persistant settings will remain unchanged.
     * <p>
     * @param virtualDevice  the virtual device to remove
     * @return 0 on success, -1 otherwise
     *
     * @see OcVirtualDevice
     */
    public int removeVirtualDevice(OcVirtualDevice virtualDevice) {
        if (virtualDevice != null) {
            return OCBridge.removeVirtualDevice(virtualDevice.getDeviceIndex());
        }
        return -1;
    }

    /**
     * Deletes a virtual device from this bridge.
     * <p>
     * All persistant settings will be deleted.
     * <p>
     * @param virtualDevice  the virtual device to delete
     * @return 0 on success, -1 otherwise
     *
     * @see OcVirtualDevice
     */
    public int deleteVirtualDevice(OcVirtualDevice virtualDevice) {
        if (virtualDevice != null) {
            return OCBridge.deleteVirtualDevice(virtualDevice.getDeviceIndex());
        }
        return -1;
    }

    /**
     * Resets this bridge.
     */
    public void reset() {
        OCMain.resetDevice(0);
    }
}

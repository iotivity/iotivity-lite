package org.iotivity.oc;

/**
 * Callback for all discovered devices.
 *
 * @see OcUtils#discoverAllDevices
 */
public interface OcDeviceDiscoveryHandler {

    /**
     * Called after a discovered device has been populated with its discovered resources.
     *
     * @param remoteDevice  the discovered device
     *
     * @see OcUtils#discoverAllDevices
     * @see OcRemoteDevice
     * @see OcRemoteResource
     */
    public void discoveredDevice(OcRemoteDevice remoteDevice);
}

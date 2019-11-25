package org.iotivity.multideviceclient;

import android.util.Log;

import org.iotivity.OCUuidUtil;
import org.iotivity.oc.OcDeviceDiscoveryHandler;
import org.iotivity.oc.OcRemoteDevice;

public class DeviceDiscoveryHandler implements OcDeviceDiscoveryHandler {

    private static final String TAG = DeviceDiscoveryHandler.class.getSimpleName();

    private MultiDeviceClientActivity activity;

    public DeviceDiscoveryHandler(MultiDeviceClientActivity activity) {
        this.activity = activity;
    }

    @Override
    public void discoveredDevice(OcRemoteDevice remoteDevice) {
        Log.d(TAG, "Remote Device Discovery Handler: " + OCUuidUtil.uuidToString(remoteDevice.getDeviceId()) + ", " + remoteDevice.getName());
        activity.addDevice(remoteDevice);
    }
}

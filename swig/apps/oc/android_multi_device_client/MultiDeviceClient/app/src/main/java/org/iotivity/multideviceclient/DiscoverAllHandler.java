package org.iotivity.multideviceclient;

import android.util.Log;

import org.iotivity.OCUuidUtil;
import org.iotivity.oc.OcDiscoverAllHandler;
import org.iotivity.oc.OcRemoteDevice;

public class DiscoverAllHandler implements OcDiscoverAllHandler {

    private static final String TAG = DiscoverAllHandler.class.getSimpleName();

    private MultiDeviceClientActivity activity;

    public DiscoverAllHandler(MultiDeviceClientActivity activity) {
        this.activity = activity;
    }

    @Override
    public void discoveredDevice(OcRemoteDevice remoteDevice) {
        Log.d(TAG, "Remote Device Discovery Handler: " + OCUuidUtil.uuidToString(remoteDevice.getDeviceId()) + ", " + remoteDevice.getName());
        activity.addDevice(remoteDevice);
    }
}

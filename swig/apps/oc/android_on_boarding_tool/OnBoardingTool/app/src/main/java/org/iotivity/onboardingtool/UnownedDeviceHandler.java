package org.iotivity.onboardingtool;

import android.util.Log;

import org.iotivity.OCEndpoint;
import org.iotivity.OCMain;
import org.iotivity.OCObtDiscoveryHandler;
import org.iotivity.OCUuidUtil;
import org.iotivity.OCUuid;

public class UnownedDeviceHandler implements OCObtDiscoveryHandler {

    private static final String TAG = UnownedDeviceHandler.class.getSimpleName();

    private OnBoardingActivity activity;

    public UnownedDeviceHandler(OnBoardingActivity activity) {
        this.activity = activity;
    }

    @Override
    public void handler(OCUuid uuid, OCEndpoint endpoints) {
        String deviceId = OCUuidUtil.uuidToString(uuid);
        Log.d(TAG, "discovered unowned device: " + deviceId + " at:");
        while (endpoints != null) {
            String[] endpointStr = new String[1];
            OCMain.endpointToString(endpoints, endpointStr);
            Log.d(TAG, endpointStr[0]);
            endpoints = endpoints.getNext();
        }

        activity.addUnownedDevice(deviceId);
    }
}

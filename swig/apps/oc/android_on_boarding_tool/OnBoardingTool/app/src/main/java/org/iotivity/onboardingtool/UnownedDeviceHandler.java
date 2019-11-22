package org.iotivity.onboardingtool;

import android.util.Log;

import org.iotivity.OCEndpoint;
import org.iotivity.OCObtDiscoveryHandler;
import org.iotivity.OCQos;
import org.iotivity.OCUuid;
import org.iotivity.OCUuidUtil;
import org.iotivity.oc.OcUtils;

public class UnownedDeviceHandler implements OCObtDiscoveryHandler {

    private static final String TAG = UnownedDeviceHandler.class.getSimpleName();

    private OnBoardingActivity activity;

    public UnownedDeviceHandler(OnBoardingActivity activity) {
        this.activity = activity;
    }

    @Override
    public void handler(OCUuid uuid, OCEndpoint endpoints) {
        OCEndpoint ep = endpoints;
        String deviceId = OCUuidUtil.uuidToString(uuid);
        Log.d(TAG, "discovered unowned device: " + deviceId + " at:");
        while (endpoints != null) {
            String endpointStr = OcUtils.endpointToString(endpoints);
            Log.d(TAG, endpointStr);
            endpoints = endpoints.getNext();
        }

        OcUtils.doGet("/oic/d", ep, null, new GetDeviceNameHandler(activity, false), OCQos.HIGH_QOS);
    }
}

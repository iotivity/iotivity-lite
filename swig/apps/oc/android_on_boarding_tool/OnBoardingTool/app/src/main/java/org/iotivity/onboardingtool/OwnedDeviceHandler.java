package org.iotivity.onboardingtool;

import android.util.Log;

import org.iotivity.OCEndpoint;
import org.iotivity.OCObtDiscoveryHandler;
import org.iotivity.OCQos;
import org.iotivity.OCUuid;
import org.iotivity.OCUuidUtil;
import org.iotivity.oc.OcUtils;

public class OwnedDeviceHandler implements OCObtDiscoveryHandler {

    private static final String TAG = OwnedDeviceHandler.class.getSimpleName();

    private OnBoardingActivity activity;

    public OwnedDeviceHandler(OnBoardingActivity activity) {
        this.activity = activity;
    }

    @Override
    public void handler(OCUuid uuid, OCEndpoint[] endpoints) {
        OCEndpoint ep = endpoints;
        String deviceId = OCUuidUtil.uuidToString(uuid);
        Log.d(TAG, "discovered owned device: " + deviceId + " at:");
        for (OCEndpoint endpoint : endpoints) {
            String endpointStr = OcUtils.endpointToString(endpoint);
            Log.d(TAG, endpointStr);
        }

        OcUtils.doGet("/oic/d", ep, null, new GetDeviceNameHandler(activity, true), OCQos.LOW_QOS);
    }
}

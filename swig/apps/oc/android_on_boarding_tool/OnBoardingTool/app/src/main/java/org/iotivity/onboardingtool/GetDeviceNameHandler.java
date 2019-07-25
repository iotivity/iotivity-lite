package org.iotivity.onboardingtool;

import android.util.Log;

import org.iotivity.*;

public class GetDeviceNameHandler implements OCResponseHandler {

    private static final String TAG = UnownedDeviceHandler.class.getSimpleName();

    private OnBoardingActivity activity;
    private boolean ownedList;


    public GetDeviceNameHandler(OnBoardingActivity activity, boolean ownedList) {
        this.activity = activity;
        this.ownedList = ownedList;
    }

    @Override
    public void handler(OCClientResponse response) {
        Log.d(TAG, "Get Device Name Handler:");
        OCRepresentation rep = response.getPayload();
        String n = null;
        String di = null;
        while (rep != null) {
            switch (rep.getType()) {
                case OC_REP_STRING:
                    if ("n".equals(rep.getName())) {
                        n = rep.getValue().getString();
                    }
                    if ("di".equals(rep.getName())) {
                        di = rep.getValue().getString();
                    }
                    break;
                default:
                    break;
            }
            rep = rep.getNext();
        }

        if ((di != null) && (n != null)) {
            if (ownedList) {
                activity.addOwnedDevice(new OcfDeviceInfo(OCUuidUtil.stringToUuid(di), n));
            } else {
                activity.addUnownedDevice(new OcfDeviceInfo(OCUuidUtil.stringToUuid(di), n));
            }
        }
    }
}

package org.iotivity.onboardingtool;

import android.util.Log;

import org.iotivity.OCClientResponse;
import org.iotivity.OCResponseHandler;
import org.iotivity.OCUuidUtil;
import org.iotivity.oc.OcCborException;
import org.iotivity.oc.OcRepresentation;

public class GetDeviceNameHandler implements OCResponseHandler {

    private static final String TAG = UnownedDeviceHandler.class.getSimpleName();

    private static final String N_KEY = "n";
    private static final String DI_KEY = "di";

    private OnBoardingActivity activity;
    private boolean ownedList;


    public GetDeviceNameHandler(OnBoardingActivity activity, boolean ownedList) {
        this.activity = activity;
        this.ownedList = ownedList;
    }

    @Override
    public void handler(OCClientResponse response) {
        Log.d(TAG, "Get Device Name Handler:");
        OcRepresentation rep = new OcRepresentation(response.getPayload());
        String n = null;
        String di = null;
        while (rep != null) {
            try {
                if (N_KEY.equals(rep.getKey())) {
                    n = rep.getString(N_KEY);
                }
                if (DI_KEY.equals(rep.getKey())) {
                    di = rep.getString(DI_KEY);
                }
            } catch (OcCborException e) {
                Log.e(TAG, e.getMessage());
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

package org.iotivity.multideviceserver;

import android.util.Log;

import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;

public class PutRefrigeratorRequestHandler implements OCRequestHandler {

    private static final String TAG = PutRefrigeratorRequestHandler.class.getSimpleName();

    private ServerActivity activity;
    private Refrigerator refrigerator;

    public PutRefrigeratorRequestHandler(ServerActivity activity, Refrigerator refrigerator) {
        this.activity = activity;
        this.refrigerator = refrigerator;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        Log.d(TAG, "inside Put Refrigerator Request Handler");
        new PostRefrigeratorRequestHandler(activity, refrigerator).handler(request, interfaces);
    }
}

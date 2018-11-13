package org.iotivity.simpleserver;

import android.util.Log;

import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;

public class PutLightRequestHandler implements OCRequestHandler {

    private static final String TAG = PutLightRequestHandler.class.getSimpleName();

    private ServerActivity activity;

    public PutLightRequestHandler(ServerActivity activity) {
        this.activity = activity;
    }

    @Override
    public void handler(OCRequest request, int interfaces, Object userData) {
        Log.d(TAG, "inside Put Light Request Handler");
        new PostLightRequestHandler(activity).handler(request, interfaces, userData);
    }
}

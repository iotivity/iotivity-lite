package org.iotivity.multideviceserver;

import android.util.Log;

import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;

public class PutLightRequestHandler implements OCRequestHandler {

    private static final String TAG = PutLightRequestHandler.class.getSimpleName();

    private ServerActivity activity;
    private Light light;

    public PutLightRequestHandler(ServerActivity activity, Light light) {
        this.activity = activity;
        this.light = light;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        Log.d(TAG, "inside Put Light Request Handler");
        new PostLightRequestHandler(activity, light).handler(request, interfaces);
    }
}

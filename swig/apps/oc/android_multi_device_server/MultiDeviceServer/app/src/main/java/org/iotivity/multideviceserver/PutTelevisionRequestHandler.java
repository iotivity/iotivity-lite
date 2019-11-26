package org.iotivity.multideviceserver;

import android.util.Log;

import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;

public class PutTelevisionRequestHandler implements OCRequestHandler {

    private static final String TAG = PutTelevisionRequestHandler.class.getSimpleName();

    private ServerActivity activity;
    private Television television;

    public PutTelevisionRequestHandler(ServerActivity activity, Television television) {
        this.activity = activity;
        this.television = television;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        Log.d(TAG, "inside Television Refrigerator Request Handler");
        new PostTelevisionRequestHandler(activity, television).handler(request, interfaces);
    }
}

package org.iotivity.simpleclient;

import android.util.Log;

import org.iotivity.OCMain;
import org.iotivity.OCMainInitHandler;

public class MyInitHandler implements OCMainInitHandler {

    private static final String TAG = MyInitHandler.class.getSimpleName();

    private ClientActivity activity;

    public MyInitHandler(ClientActivity activity) {
        this.activity = activity;
    }

    @Override
    public int initialize() {
        Log.d(TAG, "inside MyInitHandler.initialize()");
        int ret = OCMain.initPlatform("Android");
        ret |= OCMain.addDevice("/oic/d", "oic.d.phone", "Kishen's Android Phone", "ocf.1.0.0", "ocf.res.1.0.0");
        return ret;
    }

    @Override
    public void registerResources() {
        Log.d(TAG, "inside MyInitHandler.registerResources()");
    }

    @Override
    public void requestEntry() {
        Log.d(TAG, "inside MyInitHandler.requestEntry()");
        MyDiscoveryHandler discoveryHandler = new MyDiscoveryHandler(activity);
        OCMain.doIPDiscovery("core.light", discoveryHandler);
    }
}

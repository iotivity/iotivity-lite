package org.iotivity.simpleclient;

import android.util.Log;

import org.iotivity.OCMainInitHandler;
import org.iotivity.oc.OcDevice;
import org.iotivity.oc.OcPlatform;
import org.iotivity.oc.OcUtils;

public class MyInitHandler implements OCMainInitHandler {

    private static final String TAG = MyInitHandler.class.getSimpleName();

    private ClientActivity activity;
    private OcPlatform ocPlatform;

    OcDevice device;

    public MyInitHandler(ClientActivity activity, OcPlatform ocPlatform) {
        this.activity = activity;
        this.ocPlatform = ocPlatform;
    }

    @Override
    public int initialize() {
        Log.d(TAG, "inside MyInitHandler.initialize()");
        int ret = ocPlatform.platformInit("Android");
        if (ret >= 0) {
            device = new OcDevice("/oic/d", "oic.d.phone", "Kishen's Android Phone", "ocf.1.0.0", "ocf.res.1.0.0");
            ret |= ocPlatform.addDevice(device);
        }

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
        OcUtils.doIPDiscovery("oic.r.switch.binary", discoveryHandler);
    }
}

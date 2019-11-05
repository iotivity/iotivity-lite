package org.iotivity.multideviceclient;

import android.util.Log;

import org.iotivity.OCMainInitHandler;
import org.iotivity.oc.OcDevice;
import org.iotivity.oc.OcPlatform;

public class InitHandler implements OCMainInitHandler {

    private static final String TAG = InitHandler.class.getSimpleName();

    private MultiDeviceClientActivity activity;
    private OcPlatform ocPlatform;

    OcDevice device;

    public InitHandler(MultiDeviceClientActivity activity, OcPlatform ocPlatform) {
        this.activity = activity;
        this.ocPlatform = ocPlatform;
    }

    @Override
    public int initialize() {
        Log.d(TAG, "inside InitHandler.initialize()");
        int ret = ocPlatform.platformInit("Android");
        if (ret >= 0) {
            device = new OcDevice("/oic/d", "oic.d.phone", "Kishen's Android Phone", "ocf.1.0.0", "ocf.res.1.0.0");
            ret |= ocPlatform.addDevice(device);
        }

        return ret;
    }

    @Override
    public void registerResources() {
        Log.d(TAG, "inside InitHandler.registerResources()");
    }

    @Override
    public void requestEntry() {
        Log.d(TAG, "inside InitHandler.requestEntry()");
    }
}

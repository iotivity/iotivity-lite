package org.iotivity.onboardingtool;

import android.util.Log;

import org.iotivity.OCMainInitHandler;
import org.iotivity.oc.OcDevice;
import org.iotivity.oc.OcPlatform;

public class ObtInitHandler implements OCMainInitHandler {

    private static final String TAG = ObtInitHandler.class.getSimpleName();

    private OnBoardingActivity activity;
    private OcPlatform obtPlatform;

    public ObtInitHandler(OnBoardingActivity activity, OcPlatform obtPlatform) {
        this.activity = activity;
        this.obtPlatform = obtPlatform;
    }

    @Override
    public int initialize() {
        Log.d(TAG, "inside ObtInitHandler.initialize()");
        int ret = obtPlatform.platformInit("OCF");
        if (ret >= 0) {
            OcDevice device = new OcDevice("/oic/d", "oic.d.dots", "OBT", "ocf.2.5.0", "ocf.res.1.3.0,ocf.sh.1.3.0");
            ret |= obtPlatform.addDevice(device);
            // Note: device must be added to platform before additional resource types can be added
            device.bindResourceType("oic.d.ams");
            device.bindResourceType("oic.d.cms");
        }

        return ret;
    }

    @Override
    public void registerResources() {
        Log.d(TAG, "inside ObtInitHandler.registerResources()");
    }

    @Override
    public void requestEntry() {
        Log.d(TAG, "inside ObtInitHandler.requestEntry()");
    }
}

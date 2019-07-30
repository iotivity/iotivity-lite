package org.iotivity.onboardingtool;

import android.util.Log;

import org.iotivity.OCMain;
import org.iotivity.OCMainInitHandler;
import org.iotivity.OCObt;

public class ObtInitHandler implements OCMainInitHandler {

    private static final String TAG = ObtInitHandler.class.getSimpleName();

    private OnBoardingActivity activity;

    public ObtInitHandler(OnBoardingActivity activity) {
        this.activity = activity;
    }

    @Override
    public int initialize() {
        Log.d(TAG, "inside ObtInitHandler.initialize()");
        int ret = OCMain.initPlatform("OCF");
        ret |= OCMain.addDevice("/oic/d", "oic.d.sensor", "OBT", "ocf.1.0.0", "ocf.res.1.0.0");
        return ret;
    }

    @Override
    public void registerResources() {
        Log.d(TAG, "inside ObtInitHandler.registerResources()");
    }

    @Override
    public void requestEntry() {
        Log.d(TAG, "inside ObtInitHandler.requestEntry()");
        OCObt.init();
    }
}

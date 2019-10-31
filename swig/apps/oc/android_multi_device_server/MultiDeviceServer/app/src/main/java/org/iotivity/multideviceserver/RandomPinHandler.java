package org.iotivity.multideviceserver;

import android.util.Log;

import org.iotivity.OCRandomPinHandler;

public class RandomPinHandler implements OCRandomPinHandler {

    private static final String TAG = RandomPinHandler.class.getSimpleName();

    private ServerActivity activity;

    public RandomPinHandler(ServerActivity activity) {
        this.activity = activity;
    }

    @Override
    public void handler(String pin) {
        Log.d(TAG, "inside Random Pin Handler");
        activity.msg("\n!!!!!!!!!!!!!!!!!!!!\nRandom PIN: " + pin + "\n!!!!!!!!!!!!!!!!!!!!\n");
        activity.printLine();
    }
}

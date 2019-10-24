package org.iotivity.onboardingtool;

import android.util.Log;
import android.widget.Toast;

import org.iotivity.OCObtStatusHandler;

public class DeleteAceHandler implements OCObtStatusHandler {

    private static final String TAG = DeleteAceHandler.class.getSimpleName();

    private OnBoardingActivity activity;

    public DeleteAceHandler(OnBoardingActivity activity) {
        this.activity = activity;
    }

    @Override
    public void handler(int status) {
        if (status < 0) {
            final String msg = "Error deleting ace, status = " + status;
            Log.d(TAG, msg);
            activity.runOnUiThread(new Runnable() {
                public void run() {
                    Toast.makeText(activity, msg, Toast.LENGTH_LONG).show();
                }
            });
        }
    }
}

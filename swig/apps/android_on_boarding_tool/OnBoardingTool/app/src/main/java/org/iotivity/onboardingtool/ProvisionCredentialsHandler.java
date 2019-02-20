package org.iotivity.onboardingtool;

import android.util.Log;
import android.widget.Toast;

import org.iotivity.OCObtStatusHandler;

public class ProvisionCredentialsHandler implements OCObtStatusHandler {

    private static final String TAG = ProvisionCredentialsHandler.class.getSimpleName();

    private OnBoardingActivity activity;

    public ProvisionCredentialsHandler(OnBoardingActivity activity) {
        this.activity = activity;
    }

    @Override
    public void handler(int status) {
        final String msg = (status >= 0) ?
                "Successfully provisioned pair-wise credentials" :
                "Error provisioning pair-wise credentials, status = " + status;

        Log.d(TAG, msg);
        activity.runOnUiThread(new Runnable() {
            public void run() {
                Toast.makeText(activity, msg, Toast.LENGTH_LONG).show();
            }
        });
    }
}

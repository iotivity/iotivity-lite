package org.iotivity.onboardingtool;

import android.util.Log;
import android.widget.Toast;

import org.iotivity.OCObtStatusHandler;

public class ProvisionRoleCertificateHandler implements OCObtStatusHandler {

    private static final String TAG = ProvisionRoleCertificateHandler.class.getSimpleName();

    private OnBoardingActivity activity;

    public ProvisionRoleCertificateHandler(OnBoardingActivity activity) {
        this.activity = activity;
    }

    @Override
    public void handler(int status) {
        final String msg = (status >= 0) ?
                "Successfully provisioned role certificate" :
                "Error provisioning role certificate, status = " + status;

        Log.d(TAG, msg);
        activity.runOnUiThread(new Runnable() {
            public void run() {
                Toast.makeText(activity, msg, Toast.LENGTH_LONG).show();
            }
        });
    }
}

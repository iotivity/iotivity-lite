package org.iotivity.onboardingtool;

import android.util.Log;
import android.widget.Toast;

import org.iotivity.OCObtStatusHandler;

public class ProvisionIdCertificateHandler implements OCObtStatusHandler {

    private static final String TAG = ProvisionIdCertificateHandler.class.getSimpleName();

    private OnBoardingActivity activity;

    public ProvisionIdCertificateHandler(OnBoardingActivity activity) {
        this.activity = activity;
    }

    @Override
    public void handler(int status) {
        final String msg = (status >= 0) ?
                "Successfully provisioned identity certificate" :
                "Error provisioning identity certificate, status = " + status;

        Log.d(TAG, msg);
        activity.runOnUiThread(new Runnable() {
            public void run() {
                Toast.makeText(activity, msg, Toast.LENGTH_LONG).show();
            }
        });
    }
}

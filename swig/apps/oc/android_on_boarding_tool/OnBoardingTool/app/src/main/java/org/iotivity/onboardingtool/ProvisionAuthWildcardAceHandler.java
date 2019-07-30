package org.iotivity.onboardingtool;

import android.util.Log;
import android.widget.Toast;

import org.iotivity.OCObtDeviceStatusHandler;
import org.iotivity.OCUuid;
import org.iotivity.OCUuidUtil;

public class ProvisionAuthWildcardAceHandler implements OCObtDeviceStatusHandler {

    private static final String TAG = ProvisionAuthWildcardAceHandler.class.getSimpleName();

    private OnBoardingActivity activity;

    public ProvisionAuthWildcardAceHandler(OnBoardingActivity activity) {
        this.activity = activity;
    }

    @Override
    public void handler(OCUuid uuid, int status) {
        String deviceId = OCUuidUtil.uuidToString(uuid);

        final String msg = (status >= 0) ?
                "Successfully provisioned auth-crypt * ACE on device " + deviceId :
                "Error provisioning auth-crypt * ACE on device " + deviceId + ", status = " + status;

        Log.d(TAG, msg);
        activity.runOnUiThread(new Runnable() {
            public void run() {
                Toast.makeText(activity, msg, Toast.LENGTH_LONG).show();
            }
        });
    }
}

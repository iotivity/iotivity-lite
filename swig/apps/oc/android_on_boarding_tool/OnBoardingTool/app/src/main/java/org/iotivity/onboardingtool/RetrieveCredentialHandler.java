package org.iotivity.onboardingtool;

import android.util.Log;
import android.widget.SimpleAdapter;
import android.widget.Toast;

import org.iotivity.OCCred;
import org.iotivity.OCCredUtil;
import org.iotivity.OCCreds;
import org.iotivity.OCObt;
import org.iotivity.OCObtCredsHandler;
import org.iotivity.OCUuidUtil;

import java.util.ArrayList;
import java.util.HashMap;

public class RetrieveCredentialHandler implements OCObtCredsHandler {

    private static final String TAG = RetrieveCredentialHandler.class.getSimpleName();

    private OnBoardingActivity activity;
    private SimpleAdapter credsAdapter;
    private ArrayList<HashMap<String, String>> credsList;

    public RetrieveCredentialHandler(OnBoardingActivity activity, SimpleAdapter credsAdapter, ArrayList<HashMap<String, String>> credsList) {
        this.activity = activity;
        this.credsAdapter = credsAdapter;
        this.credsList = credsList;
    }

    @Override
    public void handler(OCCreds creds) {
        if (creds != null) {
            CredentialListHelper clh = new CredentialListHelper(credsList);
            clh.buildList(creds);

            activity.runOnUiThread(new Runnable() {
                public void run() {
                    credsAdapter.notifyDataSetChanged();
                }
            });

            /* Free the credential structure */
            OCObt.freeCreds(creds);

        } else {
            final String msg = "No credentials found when retrieving /oic/sec/cred";
            Log.d(TAG, msg);
            activity.runOnUiThread(new Runnable() {
                public void run() {
                    Toast.makeText(activity, msg, Toast.LENGTH_LONG).show();
                }
            });
        }
    }
}

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
            OCCred cred = creds.getCredsListHead();
            while (cred != null) {
                HashMap<String, String> item = new HashMap<>();

                String line = "Id: " + Integer.toString(cred.getCredId());
                item.put("line1", line);
                Log.d(TAG, line);

                line = "Subject UUID: " + OCUuidUtil.uuidToString(cred.getSubjectUuid());
                item.put("line2", line);
                Log.d(TAG, line);

                line = "Type: " + OCCredUtil.credTypeString(cred.getCredType());
                Log.d(TAG, line);
                item.put("line3", line);

                line = "Usage: " + OCCredUtil.readCredusage(cred.getCredUsage());
                item.put("line4", line);
                Log.d(TAG, line);

                line = "Public Data Encoding: ";
                if ((cred.getPublicData() != null) && (cred.getPublicData().getData() != null) && (!cred.getPublicData().getData().isEmpty())) {
                    line += OCCredUtil.readEncoding((cred.getPublicData().getEncoding()));
                } else {
                    line += "<None>";
                }
                item.put("line5", line);
                Log.d(TAG, line);

                line = "Private Data Encoding: " + OCCredUtil.readEncoding((cred.getPrivateData().getEncoding()));
                item.put("line6", line);
                Log.d(TAG, line);

                line = "Role: ";
                if (cred.getRole() != null && !cred.getRole().isEmpty()) {
                    line += cred.getRole();
                } else {
                    line += "<None>";
                }
                item.put("line7", line);
                Log.d(TAG, line);

                line = "Authority: ";
                if (cred.getAuthority() != null && !cred.getAuthority().isEmpty()) {
                    line += cred.getAuthority();
                } else {
                    line += "<None>";
                }
                item.put("line8", line);
                Log.d(TAG, line);

                credsList.add(item);
                cred = cred.getNext();
            }

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

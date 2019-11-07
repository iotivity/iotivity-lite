package org.iotivity.onboardingtool;

import android.util.Log;

import org.iotivity.OCCred;
import org.iotivity.OCCredUtil;
import org.iotivity.OCCreds;
import org.iotivity.OCUuidUtil;

import java.util.ArrayList;
import java.util.HashMap;

public class CredentialListHelper {

    private static final String TAG = CredentialListHelper.class.getSimpleName();

    private ArrayList<HashMap<String, String>> credentialsList;

    public CredentialListHelper(ArrayList<HashMap<String, String>> credsList) {
        this.credentialsList = credsList;
    }

    public void buildList(OCCreds creds) {
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

            line = "Usage: " + OCCredUtil.readCredUsage(cred.getCredUsage());
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
            if ((cred.getRole() != null) && (!cred.getRole().isEmpty())) {
                line += cred.getRole();
            } else {
                line += "<None>";
            }
            item.put("line7", line);
            Log.d(TAG, line);

            line = "Authority: ";
            if ((cred.getAuthority() != null) && (!cred.getAuthority().isEmpty())) {
                line += cred.getAuthority();
            } else {
                line += "<None>";
            }
            item.put("line8", line);
            Log.d(TAG, line);

            credentialsList.add(item);
            cred = cred.getNext();
        }
    }
}

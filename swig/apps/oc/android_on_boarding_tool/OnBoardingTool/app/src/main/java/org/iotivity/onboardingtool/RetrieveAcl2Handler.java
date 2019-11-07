package org.iotivity.onboardingtool;

import android.util.Log;
import android.widget.SimpleAdapter;
import android.widget.Toast;

import org.iotivity.OCAceConnectionType;
import org.iotivity.OCAcePermissionsMask;
import org.iotivity.OCAceResource;
import org.iotivity.OCAceSubjectType;
import org.iotivity.OCObt;
import org.iotivity.OCObtAclHandler;
import org.iotivity.OCSecurityAce;
import org.iotivity.OCSecurityAcl;
import org.iotivity.OCUuidUtil;

import java.util.ArrayList;
import java.util.HashMap;

public class RetrieveAcl2Handler implements OCObtAclHandler {

    private static final String TAG = RetrieveAcl2Handler.class.getSimpleName();

    private OnBoardingActivity activity;
    private SimpleAdapter aclAdapter;
    private ArrayList<HashMap<String, String>> aclList;

    public RetrieveAcl2Handler(OnBoardingActivity activity, SimpleAdapter aclAdapter, ArrayList<HashMap<String, String>> aclList) {
        this.activity = activity;
        this.aclAdapter = aclAdapter;
        this.aclList = aclList;
    }

    @Override
    public void handler(OCSecurityAcl acl) {
        if (acl != null) {
            OCSecurityAce ace = acl.getSubjectsListHead();
            if (ace == null) {
                final String msg = "No security ACEs found";
                Log.d(TAG, msg);
                activity.runOnUiThread(new Runnable() {
                    public void run() {
                        Toast.makeText(activity, msg, Toast.LENGTH_LONG).show();
                    }
                });
            }

            while (ace != null) {
                HashMap<String, String> item = new HashMap<>();

                String line = "Id: " + Integer.toString(ace.getAceid());
                item.put("line1", line);
                Log.d(TAG, line);

                if (ace.getSubjectType() == OCAceSubjectType.OC_SUBJECT_UUID) {
                    line = "Subject: " + OCUuidUtil.uuidToString(ace.getSubject().getUuid());

                } else if (ace.getSubjectType() == OCAceSubjectType.OC_SUBJECT_ROLE) {
                    line = "Role / Authority: " + ace.getSubject().getRole() + " / ";

                    if ((ace.getSubject().getAuthority() != null) && (!ace.getSubject().getAuthority().isEmpty())) {
                        line += ace.getSubject().getAuthority();
                    } else {
                        line += "<None>";
                    }

                } else if (ace.getSubjectType() == OCAceSubjectType.OC_SUBJECT_CONN) {
                    line = "Connection Type: ";
                    if (ace.getSubject().getConn() == OCAceConnectionType.OC_CONN_AUTH_CRYPT) {
                        line += "auth-crypt";
                    } else {
                        line += "anon-clear";
                    }
                }

                item.put("line2", line);
                Log.d(TAG, line);

                StringBuilder permissions = new StringBuilder();
                permissions.append("Permissions:");
                if ((ace.getPermission() & OCAcePermissionsMask.CREATE) == OCAcePermissionsMask.CREATE) {
                    permissions.append(" C");
                }
                if ((ace.getPermission() & OCAcePermissionsMask.RETRIEVE) == OCAcePermissionsMask.RETRIEVE) {
                    permissions.append(" R");
                }
                if ((ace.getPermission() & OCAcePermissionsMask.UPDATE) == OCAcePermissionsMask.UPDATE) {
                    permissions.append(" U");
                }
                if ((ace.getPermission() & OCAcePermissionsMask.DELETE) == OCAcePermissionsMask.DELETE) {
                    permissions.append(" D");
                }
                if ((ace.getPermission() & OCAcePermissionsMask.NOTIFY) == OCAcePermissionsMask.NOTIFY) {
                    permissions.append(" N");
                }
                line = permissions.toString();
                item.put("line3", line);
                Log.d(TAG, line);

                StringBuilder aceResources = new StringBuilder();
                aceResources.append("Resources: ");
                OCAceResource res = ace.getResourcesListHead();
                while (res != null) {
                    if ((res.getHref() != null) && (!res.getHref().isEmpty())) {
                        aceResources.append(" " + res.getHref() + " ");
                    } else if (res.getWildcard() != null) {
                        switch (res.getWildcard()) {
                            case OC_ACE_WC_ALL:
                                aceResources.append(" *");
                                break;
                            case OC_ACE_WC_ALL_SECURED:
                                aceResources.append(" +");
                                break;
                            case OC_ACE_WC_ALL_PUBLIC:
                                aceResources.append(" -");
                                break;
                            default:
                                break;
                        }
                    }
                    res = res.getNext();
                }
                line = aceResources.toString();
                item.put("line4", line);
                Log.d(TAG, line);

                aclList.add(item);
                ace = ace.getNext();
            }

            activity.runOnUiThread(new Runnable() {
                public void run() {
                    aclAdapter.notifyDataSetChanged();
                }
            });

            /* Free the ACL structure */
            OCObt.freeAcl(acl);

        } else {
            final String msg = "No ACLs found when retrieving /oic/sec/acl2";
            Log.d(TAG, msg);
            activity.runOnUiThread(new Runnable() {
                public void run() {
                    Toast.makeText(activity, msg, Toast.LENGTH_LONG).show();
                }
            });
        }
    }
}

package org.iotivity.onboardingtool;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.util.Log;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Toast;

import org.iotivity.OCAcePermissionsMask;
import org.iotivity.OCAceWildcard;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCObtDeviceStatusHandler;
import org.iotivity.OCUuidUtil;
import org.iotivity.oc.OcAceResource;
import org.iotivity.oc.OcObt;
import org.iotivity.oc.OcSecurityAce;

import java.util.HashSet;
import java.util.Set;

class AcePropertiesHelper {

    private static final String TAG = AcePropertiesHelper.class.getSimpleName();

    private OnBoardingActivity activity;
    private OcObt obt;
    private String uuid;
    private OCObtDeviceStatusHandler provisionAce2Handler;
    private int resourceNumber;

    AcePropertiesHelper(OnBoardingActivity activity, OcObt obt, String uuid, OCObtDeviceStatusHandler provisionAce2Handler) {
        this.activity = activity;
        this.obt = obt;
        this.uuid = uuid;
        this.provisionAce2Handler = provisionAce2Handler;
    }

    void getProperties(final OcSecurityAce ace) {
        ++resourceNumber;

        final OcAceResource aceResource = new OcAceResource(ace);

        if (aceResource == null) {
            Toast.makeText(activity, "Error allocating new ace resource", Toast.LENGTH_LONG).show();
            return;
        }

        AlertDialog.Builder hrefAlertDialogBuilder = new AlertDialog.Builder(activity);

        LinearLayout layout = new LinearLayout(activity);
        layout.setLayoutParams(new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        layout.setOrientation(LinearLayout.VERTICAL);

        final EditText input = new EditText(activity);
        layout.addView(input);

        String title = activity.getString(R.string.hrefDialogTitle).replace("?", Integer.toString(resourceNumber));
        hrefAlertDialogBuilder.setTitle(title);
        hrefAlertDialogBuilder.setMessage(R.string.hrefDialogMessage);
        hrefAlertDialogBuilder.setView(layout);

        hrefAlertDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                String href = input.getText().toString().trim();
                if (!href.isEmpty()) {
                    if (href.length() > 63) {
                        href = href.substring(0, 63);
                    }

                    aceResource.setHref(href);
                    aceResource.setWildcard(OCAceWildcard.OC_ACE_NO_WC);

                    getPermissions(ace);

                } else {
                    AlertDialog.Builder wildcardAlertDialogBuilder = new AlertDialog.Builder(activity);
                    String title = activity.getResources().getString(R.string.wildcardDialogTitle).replace("?", Integer.toString(resourceNumber));
                    wildcardAlertDialogBuilder.setTitle(title);
                    wildcardAlertDialogBuilder.setItems(R.array.wildcardOptions, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            switch (which) {
                                case 0:
                                    aceResource.setWildcard(OCAceWildcard.OC_ACE_NO_WC);
                                    break;
                                case 1:
                                    aceResource.setWildcard(OCAceWildcard.OC_ACE_WC_ALL);
                                    break;
                                case 2:
                                    aceResource.setWildcard(OCAceWildcard.OC_ACE_WC_ALL_SECURED);
                                    break;
                                case 3:
                                    aceResource.setWildcard(OCAceWildcard.OC_ACE_WC_ALL_PUBLIC);
                                    break;
                                default:
                                    break;
                            }

                            getPermissions(ace);
                        }
                    });

                    Dialog wildcardDialog = wildcardAlertDialogBuilder.create();
                    wildcardDialog.show();
                }
            }
        });

        Dialog hrefDialog = hrefAlertDialogBuilder.create();
        hrefDialog.show();
    }

    private void getPermissions(final OcSecurityAce ace) {
        final Set<Integer> permissions = new HashSet<>();
        AlertDialog.Builder permissionsAlertDialogBuilder = new AlertDialog.Builder(activity);
        permissionsAlertDialogBuilder.setTitle(R.string.permissionsDialogTitle);
        permissionsAlertDialogBuilder.setMultiChoiceItems(R.array.permissions, null, new DialogInterface.OnMultiChoiceClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which, boolean isChecked) {
                if (isChecked) {
                    permissions.add(which);
                } else {
                    if (permissions.contains(which)) {
                        permissions.remove(which);
                    }
                }
            }
        });

        permissionsAlertDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                if (!permissions.isEmpty()) {
                    for (int permission : permissions) {
                        switch (permission) {
                            case 0:
                                ace.addPermission(OCAcePermissionsMask.CREATE);
                                break;
                            case 1:
                                ace.addPermission(OCAcePermissionsMask.RETRIEVE);
                                break;
                            case 2:
                                ace.addPermission(OCAcePermissionsMask.UPDATE);
                                break;
                            case 3:
                                ace.addPermission(OCAcePermissionsMask.DELETE);
                                break;
                            case 4:
                                ace.addPermission(OCAcePermissionsMask.NOTIFY);
                                break;
                            default:
                                break;
                        }
                    }
                }

                new Thread(new Runnable() {
                    public void run() {
                        if (obt.provisionAce(OCUuidUtil.stringToUuid(uuid), ace, provisionAce2Handler) < 0) {
                            final String msg = "Failed to provision ace credentials for " + uuid;
                            Log.d(TAG, msg);
                            activity.runOnUiThread(new Runnable() {
                                public void run() {
                                    Toast.makeText(activity, msg, Toast.LENGTH_LONG).show();
                                }
                            });
                        }
                    }
                }).start();
            }
        });

        Dialog permissionsDialog = permissionsAlertDialogBuilder.create();
        permissionsDialog.show();
    }
}

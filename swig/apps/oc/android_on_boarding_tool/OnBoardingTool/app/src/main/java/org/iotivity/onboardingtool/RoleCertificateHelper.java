package org.iotivity.onboardingtool;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.util.Log;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Toast;

import org.iotivity.OCObtStatusHandler;
import org.iotivity.OCRole;
import org.iotivity.OCUuidUtil;
import org.iotivity.oc.OcObt;

class RoleCertificateHelper {

    private static final String TAG = RoleCertificateHelper.class.getSimpleName();

    private OnBoardingActivity activity;
    private OcObt obt;
    private String uuid;
    private OCObtStatusHandler provisionRoleCertificateHandler;
    private OCRole roles;

    RoleCertificateHelper(OnBoardingActivity activity, OcObt obt, String uuid, OCObtStatusHandler provisionRoleCertificateHandler) {
        this.activity = activity;
        this.obt = obt;
        this.uuid = uuid;
        this.provisionRoleCertificateHandler = provisionRoleCertificateHandler;
    }

    void getRoles(final OCRole roles) {

        AlertDialog.Builder roleDialogBuilder = new AlertDialog.Builder(activity);

        LinearLayout layout = new LinearLayout(activity);
        layout.setLayoutParams(new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        layout.setOrientation(LinearLayout.VERTICAL);

        final EditText input = new EditText(activity);
        layout.addView(input);

        String title = activity.getString(R.string.roleDialogTitle);
        roleDialogBuilder.setTitle(title);
        roleDialogBuilder.setMessage(R.string.roleDialogMessage);
        roleDialogBuilder.setView(layout);

        roleDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                String role = input.getText().toString().trim();
                if (!role.isEmpty()) {
                    if (role.length() > 63) {
                        role = role.substring(0, 63);
                    }

                    final String certRole = role;

                    AlertDialog.Builder authorityAlertBuilder = new AlertDialog.Builder(activity);

                    LinearLayout layout = new LinearLayout(activity);
                    layout.setLayoutParams(new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
                    layout.setOrientation(LinearLayout.VERTICAL);

                    final EditText input = new EditText(activity);
                    layout.addView(input);

                    String title = activity.getString(R.string.authorityDialogTitle);
                    authorityAlertBuilder.setTitle(title);
                    authorityAlertBuilder.setMessage(R.string.authorityDialogMessage);
                    authorityAlertBuilder.setView(layout);

                    authorityAlertBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            String authority = input.getText().toString().trim();
                            if (!authority.isEmpty()) {
                                if (authority.length() > 63) {
                                    authority = authority.substring(0, 63);
                                }
                            } else {
                                authority = null;
                            }

                            final String certAuthority = authority;

                            RoleCertificateHelper.this.roles = obt.addRoleId(roles, certRole, certAuthority);

                            AlertDialog.Builder moreRolesAlertDialogBuilder = new AlertDialog.Builder(activity);
                            moreRolesAlertDialogBuilder.setTitle(R.string.addMoreRolesDialogMessage);

                            moreRolesAlertDialogBuilder.setPositiveButton("Yes"/*android.R.string.yes*/, new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    getRoles(RoleCertificateHelper.this.roles);
                                }
                            });

                            moreRolesAlertDialogBuilder.setNegativeButton("No"/*android.R.string.no*/, new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    new Thread(new Runnable() {
                                        public void run() {
                                            if (obt.provisionRoleCertificate(RoleCertificateHelper.this.roles, OCUuidUtil.stringToUuid(uuid), provisionRoleCertificateHandler) < 0) {
                                                final String msg = "Failed to provision role certificate for uuid " + uuid;
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

                            Dialog moreRolesDialog = moreRolesAlertDialogBuilder.create();
                            moreRolesDialog.show();
                        }
                    });

                    Dialog authorityDialog = authorityAlertBuilder.create();
                    authorityDialog.show();
                }
            }
        });

        Dialog roleDialog = roleDialogBuilder.create();
        roleDialog.show();
    }
}

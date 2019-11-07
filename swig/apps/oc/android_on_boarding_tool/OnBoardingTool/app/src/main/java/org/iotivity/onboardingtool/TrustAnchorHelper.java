package org.iotivity.onboardingtool;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.graphics.Typeface;
import android.util.Log;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Toast;

import org.iotivity.OCPki;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

class TrustAnchorHelper {

    private static final String TAG = TrustAnchorHelper.class.getSimpleName();

    private OnBoardingActivity activity;

    TrustAnchorHelper(OnBoardingActivity activity) {
        this.activity = activity;
    }

    void installTrustAnchor() {

        AlertDialog.Builder installTrustAnchorDialogBuilder = new AlertDialog.Builder(activity);

        LinearLayout layout = new LinearLayout(activity);
        layout.setLayoutParams(new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        layout.setOrientation(LinearLayout.VERTICAL);

        final EditText input = new EditText(activity);
        Typeface tf = Typeface.create(Typeface.MONOSPACE, Typeface.NORMAL);
        input.setTypeface(tf);
        input.setTextSize(Math.min(input.getTextSize(), 12));
        layout.addView(input);

        String title = activity.getString(R.string.installTrustAnchor);
        installTrustAnchorDialogBuilder.setTitle(title);
        installTrustAnchorDialogBuilder.setMessage(R.string.trustAnchorMessage);
        installTrustAnchorDialogBuilder.setView(layout);

        installTrustAnchorDialogBuilder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                String certificate = input.getText().toString().trim();
                if (!certificate.isEmpty()) {
                    Log.d(TAG, certificate);

                    ByteArrayOutputStream certBuffer = new ByteArrayOutputStream();

                    try {
                        certBuffer.write(certificate.getBytes());
                        int rootCaCredentialId = OCPki.addMfgTrustAnchor(0, certBuffer.toByteArray());

                        final String msg = (rootCaCredentialId >= 0) ?
                                "Successfully installed root certificate" :
                                "Error installing root certificate";
                        Log.d(TAG, msg);
                        activity.runOnUiThread(new Runnable() {
                            public void run() {
                                Toast.makeText(activity, msg, Toast.LENGTH_LONG).show();
                            }
                        });

                    } catch (IOException e) {
                        final String msg = "Error reading input, certificate not installed";
                        Log.d(TAG, msg);
                        activity.runOnUiThread(new Runnable() {
                            public void run() {
                                Toast.makeText(activity, msg, Toast.LENGTH_LONG).show();
                            }
                        });
                    }
                }
            }
        });

        installTrustAnchorDialogBuilder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
            }
        });

        Dialog installTrustAnchorDialog = installTrustAnchorDialogBuilder.create();
        installTrustAnchorDialog.show();
    }
}

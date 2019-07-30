package org.iotivity.onboardingtool;

import android.util.Log;

import org.iotivity.OCFactoryPresetsHandler;
import org.iotivity.OCPki;
import org.iotivity.OCSpTypesMask;
import org.iotivity.oc.OcObt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class FactoryPresetsHandler implements OCFactoryPresetsHandler {

    private static final String TAG = FactoryPresetsHandler.class.getSimpleName();

    private OnBoardingActivity activity;

    public FactoryPresetsHandler(OnBoardingActivity activity) {
        this.activity = activity;
    }

    @Override
    public void handler(long deviceIndex) {
        Log.d(TAG, "inside the FactoryPresetsHandler, deviceIndex  = " + deviceIndex);

        // Shutdown and re-init instance
        if (activity.obt != null) {
            activity.obt.shutdown();
        }
        activity.ownedDeviceList.clear();
        activity.unownedDeviceList.clear();
        activity.obt = new OcObt();

        byte[] cert = getFileBytes("pki_certs/ee.pem");
        if (cert == null) {
            Log.e(TAG, "Failed to read certificates");
            return;
        }

        byte[] key = getFileBytes("pki_certs/key.pem");
        if (key == null) {
            Log.e(TAG, "Failed to read private key");
            return;
        }

        int eeCredId = OCPki.addMfgCert(deviceIndex, cert, key);
        Log.d(TAG, "addMfgCert() credId = " + eeCredId);
        if (eeCredId < 0) {
            Log.e(TAG, "Error installing manufacturer ee certificate");
            return;
        }

        byte[] subCa = getFileBytes("pki_certs/subca1.pem");
        if (subCa == null) {
            Log.e(TAG, "Failed to read sub ca cetificate");
            return;
        }

        int subCaCredId = OCPki.addMfgIntermediateCert(deviceIndex, eeCredId, subCa);
        Log.d(TAG, "addMfgIntermediateCert() result = " + subCaCredId);
        if (subCaCredId < 0) {
            Log.e(TAG, "Error installing intermediate ca certificate");
            return;
        }

        byte[] rootCa1 = getFileBytes("pki_certs/rootca1.pem");
        if (rootCa1 == null) {
            System.err.println("Failed to read root ca1 cetificate");
            return;
        }

        int rootCaCredId = OCPki.addMfgTrustAnchor(deviceIndex, rootCa1);
        System.out.println("addMfgTrustAnchor() result = " + rootCaCredId);
        if (rootCaCredId < 0) {
            System.err.println("Error installing root ca1 certificate");
            return;
        }

        byte[] rootCa2 = getFileBytes("pki_certs/rootca2.pem");
        if (rootCa2 == null) {
            System.err.println("Failed to read root ca2 cetificate");
            return;
        }

        rootCaCredId = OCPki.addMfgTrustAnchor(deviceIndex, rootCa2);
        System.out.println("addMfgTrustAnchor() result = " + rootCaCredId);
        if (rootCaCredId < 0) {
            System.err.println("Error installing root ca2 certificate");
            return;
        }

        OCPki.setSecurityProfile(deviceIndex, OCSpTypesMask.BLACK, OCSpTypesMask.BLACK, eeCredId);
        Log.d(TAG, "setSecurityProfile()");
    }

    public byte[] getFileBytes(String filepath) {

        ByteArrayOutputStream baos = null;
        try {
            InputStream is = activity.getAssets().open(filepath);
            Log.d(TAG, "reading file " + filepath);

            try {
                byte[] buffer = new byte[8192];
                baos = new ByteArrayOutputStream();
                int length = 0;
                while ((length = is.read(buffer)) != -1) {
                    Log.d(TAG, "bytes read = " + length);
                    baos.write(buffer, 0, length);
                }
            } catch (IOException e) {
                Log.e(TAG, "Error reading file " + filepath);
            } finally {
                try {
                    if (baos != null) {
                        baos.close();
                    }
                } catch (IOException e) {
                    // ignore
                }
                try {
                    if (is != null) {
                        is.close();
                    }
                } catch (IOException e) {
                    // ignore
                }
            }

        } catch (IOException e) {
            Log.e(TAG, "Failed to read " + filepath);
        }

        return ((baos != null) ? baos.toByteArray() : null);
    }
}

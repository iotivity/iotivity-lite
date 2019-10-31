package java_oc_onboarding_tool;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.IOException;

import org.iotivity.OCFactoryPresetsHandler;
import org.iotivity.OCPki;

import org.iotivity.oc.OcObt;

public class FactoryPresetsHandler implements OCFactoryPresetsHandler {

    @Override
    public void handler(long deviceIndex) {
        System.out.println("inside the FactoryPresetsHandler, deviceIndex  = " + deviceIndex);

        // Shutdown and re-init instance
        if (ObtMain.obt != null) {
            ObtMain.obt.shutdown();
        }
        ObtMain.ownedDevices.clear();
        ObtMain.unownedDevices.clear();
        ObtMain.obt = new OcObt();

        byte[] rootCa1 = getFileBytes("../../../../apps/pki_certs/rootca1.pem");
        if (rootCa1 == null) {
            System.err.println("Failed to read root ca1 certificate");
            return;
        }

        int rootCaCredId = OCPki.addMfgTrustAnchor(deviceIndex, rootCa1);
        System.out.println("addMfgTrustAnchor() result = " + rootCaCredId);
        if (rootCaCredId < 0) {
            System.err.println("Error installing root ca1 certificate");
            return;
        }

        byte[] rootCa2 = getFileBytes("../../../../apps/pki_certs/rootca2.pem");
        if (rootCa2 == null) {
            System.err.println("Failed to read root ca2 certificate");
            return;
        }

        rootCaCredId = OCPki.addMfgTrustAnchor(deviceIndex, rootCa2);
        System.out.println("addMfgTrustAnchor() result = " + rootCaCredId);
        if (rootCaCredId < 0) {
            System.err.println("Error installing root ca2 certificate");
            return;
        }
    }

    public static byte[] getFileBytes(String filepath) {
        File file = new File(filepath);
        System.out.println("getting bytes for file " + file.getAbsolutePath());

        InputStream fis = null;
        try {
            fis = new FileInputStream(file);
            System.out.println("reading file " + file.getAbsolutePath());
        } catch (FileNotFoundException e) {
            System.err.println("Failed to read " + filepath);
            return null;
        }

        ByteArrayOutputStream baos = null;
        try {
            byte[] buffer = new byte[8192];
            baos = new ByteArrayOutputStream();
            int length = 0;
            while ((length = fis.read(buffer)) != -1) {
                System.out.println("bytes read = " + length);
                baos.write(buffer, 0, length);
            }
        } catch (IOException e) {
            System.err.println("Error reading file " + file.getAbsolutePath());
        } finally {
            try {
                if (baos != null) {
                    baos.close();
                }
            } catch (IOException e) {
                // ignore
            }
            try {
                if (fis != null) {
                    fis.close();
                }
            } catch (IOException e) {
                // ignore
            }
        }

        return ((baos != null) ? baos.toByteArray() : null);
    }
}

package java_smart_home_server;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.InputStream;
import java.io.IOException;

public class SmartHomeIntrospectionData {

    // never instantiated
    private SmartHomeIntrospectionData() {
    }

    public static byte[] getCborFileBytes(String filePath) {
        File file = new File(filePath);
        System.out.println("getting bytes for cbor file " + file.getAbsolutePath());

        InputStream fis = null;
        try {
            fis = new FileInputStream(file);
            System.out.println("reading file " + file.getAbsolutePath());

        } catch (FileNotFoundException e) {
            System.err.println("Failed to read " + filePath);
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

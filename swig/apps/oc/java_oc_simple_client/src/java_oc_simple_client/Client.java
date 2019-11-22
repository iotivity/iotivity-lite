package java_oc_simple_client;

import org.iotivity.*;
import org.iotivity.oc.*;

public class Client {

    static private OcPlatform platform = OcPlatform.getInstance();
    static private Thread mainThread = Thread.currentThread();

    static private Thread shutdownHook = new Thread() {
        public void run() {
            System.out.println("Calling platform shutdown.");
            platform.systemShutdown();
            mainThread.interrupt();
        }
    };

    public static void main(String argv[]) {
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        String creds_path = "./simpleclient_creds/";
        java.io.File directory = new java.io.File(creds_path);
        if (!directory.exists()) {
            directory.mkdir();
        }
        System.out.println("Storage Config PATH : " + directory.getPath());
        if (0 != OCStorage.storageConfig(directory.getPath())) {
            System.err.println("Failed to setup Storage Config.");
        }

        MyInitHandler handler = new MyInitHandler(platform);
        platform.systemInit(handler);

        try {
            Thread.sleep(Long.MAX_VALUE);
        } catch (InterruptedException e) {
            System.err.println(e);
        }

        System.exit(0);
    }
}

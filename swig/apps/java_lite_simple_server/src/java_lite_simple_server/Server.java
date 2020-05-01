package java_lite_simple_server;

import org.iotivity.*;

public class Server {

    static private Thread mainThread;
    static private Thread shutdownHook = new Thread() {
        public void run() {
            System.out.println("Calling main_shutdown.");
            OCMain.mainShutdown();
            mainThread.interrupt();
        }
    };

    public static void main(String argv[]) {
        mainThread = Thread.currentThread();
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        String creds_path =  "./simpleserver_creds/";
        java.io.File directory = new java.io.File(creds_path);
        if (! directory.exists()) {
            directory.mkdir();
        }
        System.out.println("Storage Config PATH : " + directory.getPath());
        if (0 != OCStorage.storageConfig(directory.getPath())) {
            System.err.println("Failed to setup Storage Config.");
        }

        MyInitHandler h = new MyInitHandler();
        int init_ret = OCMain.mainInit(h);
        if (init_ret < 0) {
            System.exit(init_ret);
        }

        if (OCMain.isOwnedDevice(0)) {
            System.out.println("Sever is already owned");
        } else {
            System.out.println("Sever is currently Un-owned");
        }
        OCMain.addOwnershipStatusHandler(new OwnershipStatusHandler());

        try {
            Thread.sleep(Long.MAX_VALUE);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        System.exit(0);
    }
}

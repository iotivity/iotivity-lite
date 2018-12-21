package java_lite_simple_server;

import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.iotivity.*;

public class Server {
    static {
        System.loadLibrary("iotivity-lite-jni");
    }

    public final static Lock lock = new ReentrantLock();
    public static Condition cv = lock.newCondition();

    public static final long NANOS_PER_SECOND = 1000000000; // 1.e09

    static private boolean quit;
    static private Thread mainThread;
    static private Thread shutdownHook = new Thread() {
        public void run() {
            quit = true;
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
        OCStorage.storageConfig(directory.getPath());

        MyInitHandler h = new MyInitHandler();
        int init_ret = OCMain.mainInit(h);
        if (init_ret < 0) {
            System.exit(init_ret);
        }

        while (!quit) {
            long next_event = OCMain.mainPoll();
            lock.lock();
            try {
                if (next_event == 0) {
                    //System.out.println("Calling cv.await");
                    cv.await();
                } else {
                    long now = OCClock.clockTime();
                    long timeToWait = (NANOS_PER_SECOND / OCClock.OC_CLOCK_SECOND) * (next_event - now);
                    //System.out.println("Calling cv.awaitNanos " + timeToWait);
                    cv.awaitNanos(timeToWait);
                }
            } catch (InterruptedException e) {
                System.out.println(e);
            } finally {
                lock.unlock();
            }
        }

        System.exit(0);
    }
}

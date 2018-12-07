package java_lite_simple_client;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.iotivity.*;

import java_lite_simple_server.Server;

public class Client {
    static {
        System.loadLibrary("iotivity-lite-jni");
    }

    public final static Lock lock = new ReentrantLock();
    public static Condition cv = lock.newCondition();

    public static final long NANOS_PER_SECOND = 1000000000; // 1.e09
    public static final long CLOCK_TICKS_PER_SECOND = OCClock.OC_CLOCK_SECOND;

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

        String osName = System.getProperty("os.name");
        boolean isLinux = (osName != null) && osName.toLowerCase().contains("linux");
        System.out.println("OS Name = " + osName + ", isLinux = " + isLinux);

        try {
            String path = Client.class.getProtectionDomain().getCodeSource().getLocation().getPath();
            String decodedPath = URLDecoder.decode(path, "UTF-8");
            String creds_path = decodedPath + "simpleclient_creds/";
            java.io.File directory = new java.io.File(creds_path);
            if (! directory.exists()) {
                directory.mkdir();
            }
            System.out.println("Storage Config PATH : " + creds_path);
            OCStorage.storage_config(creds_path);
        } catch (UnsupportedEncodingException e1) {
            System.err.println("Failed to find path for security data.");
            e1.printStackTrace();
        }

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
                    System.out.println("Calling cv.await");
                    cv.await();
                } else {
                    if (isLinux) {
                        // For Linux next_event is absolute time.
                        // Decrement next_event by the current time to get the nanoseconds to wait.
                        long next_event_secs = (next_event / CLOCK_TICKS_PER_SECOND);
                        long next_event_nanos = (next_event % CLOCK_TICKS_PER_SECOND) * (NANOS_PER_SECOND / CLOCK_TICKS_PER_SECOND);

                        long now = OCClock.clockTime();
                        long now_secs = (now / CLOCK_TICKS_PER_SECOND);
                        long now_nanos = (now % CLOCK_TICKS_PER_SECOND) * (NANOS_PER_SECOND / CLOCK_TICKS_PER_SECOND);

                        long timeToWait = ((next_event_secs * NANOS_PER_SECOND) + next_event_nanos) -
                                          ((now_secs * NANOS_PER_SECOND) + now_nanos);
                        timeToWait %= (NANOS_PER_SECOND * 10); // never more than 10 seconds
                        //System.out.println("Calling cv.awaitNanos " + timeToWait);
                        cv.awaitNanos(timeToWait);
                    } else {
                        //System.out.println("Calling cv.awaitNanos " + next_event);
                        long now = OCClock.clockTime();
                        cv.awaitNanos((next_event - now) * 1000000 / OCClock.OC_CLOCK_SECOND);
                    }
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

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

        OCStorage.storage_config("./simpleserver_creds");
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
                        //System.out.println("Calling cv.awaitNanos " + timeToWait);
                        cv.awaitNanos(timeToWait);
                    } else {
                        // For Windows next_event is the number of nanoseconds to wait
                        //System.out.println("Calling cv.awaitNanos " + next_event);
                        cv.awaitNanos(next_event);
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

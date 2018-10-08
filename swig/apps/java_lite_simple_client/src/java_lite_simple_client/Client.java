package java_lite_simple_client;

import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.iotivity.*;
public class Client {
    static {
        System.loadLibrary("iotivity-lite-jni");
      }

    public final static Lock lock = new ReentrantLock();
    public static Condition cv = lock.newCondition();

    public static void main(String argv[]) {
        OCStorage.storage_config("./simpleclient_creds");
        MyInitHandler h = new MyInitHandler();
        int init_ret = OCMain.mainInit(h);
        if (init_ret < 0) {
            System.exit(init_ret);
        }

            while(!Thread.currentThread().isInterrupted()) {
                long next_event = OCMain.mainPoll().longValue();
                lock.lock();
                try {
                if (next_event == 0) {
                    System.out.println("Calling cv.await");
                    cv.await();
                } else {
                    System.out.println("Calling cv.awaitNanos " + next_event);
                    cv.awaitNanos(next_event);
                }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                } finally {
                    lock.unlock();
                }
            }
        System.out.println("Calling mainShutdown.");
        OCMain.mainShutdown();
        System.exit(0);
      }

}

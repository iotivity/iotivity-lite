package java_lite_simple_server_windows;

import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.iotivity.*;
public class server {
    static {
        System.loadLibrary("iotivity-lite-java");
      }

    public final static Lock lock = new ReentrantLock();
    public static Condition cv = lock.newCondition();
    //private static boolean quit = false;

    public static void main(String argv[]) {
        storage.storage_config("./simpleserver_creds");
        MyInitHandler h = new MyInitHandler();
        int init_ret = api.main_init(h);
        if (init_ret < 0) {
            System.exit(init_ret);
        }

            while(!Thread.currentThread().isInterrupted()) {
                long next_event = api.main_poll().longValue();
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
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } finally {
                    lock.unlock();
                }
            }
        System.out.println("Calling main_shutdown.");
        api.main_shutdown();
        System.exit(0);
      }

}

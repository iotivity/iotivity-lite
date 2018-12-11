package org.iotivity.simpleserver;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.ScrollView;
import android.widget.TextView;

import org.iotivity.OCClock;
import org.iotivity.OCMain;
import org.iotivity.OCStorage;

import java.io.File;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class ServerActivity extends AppCompatActivity {

    static {
        System.loadLibrary("c++_shared");
        System.loadLibrary("iotivity-lite-jni");
    }

    public final Lock lock = new ReentrantLock();
    public Condition cv = lock.newCondition();

    public TextView mConsoleTextView;
    public ScrollView mScrollView;

    private static final String TAG = ServerActivity.class.getSimpleName();

    private boolean quit;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mConsoleTextView = (TextView) findViewById(R.id.consoleTextView);
        mConsoleTextView.setMovementMethod(new ScrollingMovementMethod());
        mScrollView = (ScrollView) findViewById(R.id.scrollView);
        mScrollView.fullScroll(View.FOCUS_DOWN);

        if (savedInstanceState == null) {
            // start first time only
            File credsDir = new File(getExternalFilesDir(null), "simpleserver_creds");
            Log.i(TAG, "Credentials directory is " + credsDir.getAbsolutePath());
            if (!credsDir.exists()) {
                boolean mkDirResult = credsDir.mkdir();
                if (mkDirResult) {
                    Log.i(TAG, "Created credentials directory " + credsDir.getAbsolutePath());
                } else {
                    Log.e(TAG, "Failed to create credentials directory " + credsDir.getAbsolutePath());
                }
            }
            OCStorage.storageConfig(credsDir.getAbsolutePath());

            MyInitHandler handler = new MyInitHandler(this);
            int initReturn = OCMain.mainInit(handler);
            if (initReturn < 0) {
                Log.e(TAG, "Error in mainInit return code = " + initReturn);
                return;
            }

            new Thread(new Runnable() {
                public void run() {
                    eventLoop();
                }
            }).start();
        }
    }

    @Override
    protected void onDestroy() {
        quit = true;
        Log.d(TAG, "Calling main_shutdown.");
        OCMain.mainShutdown();
        super.onDestroy();
    }

    public void msg(final String text) {
        runOnUiThread(new Runnable() {
            public void run() {
                mConsoleTextView.append("\n");
                mConsoleTextView.append(text);
                mScrollView.fullScroll(View.FOCUS_DOWN);
            }
        });
        Log.i(TAG, text);
    }

    public void printLine() {
        msg("------------------------------------------------------------------------");
    }

    private void eventLoop() {
        while (!quit) {
            long nextEvent = OCMain.mainPoll();
            lock.lock();
            try {
                if (nextEvent == 0) {
                    cv.await();
                } else {
                    long now = OCClock.clockTime();
                    // nextEvent and now are in microseconds
                    long timeToWait = (nextEvent - now) * 1000;
                    cv.awaitNanos(timeToWait);
                }
            } catch (InterruptedException e) {
                Log.d(TAG, e.getMessage());
            } finally {
                lock.unlock();
            }
        }
    }
}

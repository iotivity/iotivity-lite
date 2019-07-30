package org.iotivity.simpleclient;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.ScrollView;
import android.widget.TextView;

import org.iotivity.oc.OcPlatform;

public class ClientActivity extends AppCompatActivity {

    private static final String TAG = ClientActivity.class.getSimpleName();

    private TextView mConsoleTextView;
    private ScrollView mScrollView;

    private OcPlatform ocPlatform;

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
            ocPlatform = OcPlatform.getInstance();
            MyInitHandler handler = new MyInitHandler(this, ocPlatform);
            ocPlatform.systemInit(handler);
        }
    }

    @Override
    protected void onDestroy() {
        Log.d(TAG, "Calling Shutdown.");
        ocPlatform.systemShutdown();
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
}

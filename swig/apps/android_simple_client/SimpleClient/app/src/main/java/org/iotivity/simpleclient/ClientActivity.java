package org.iotivity.simpleclient;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.ScrollView;
import android.widget.TextView;

import org.iotivity.OCMain;

public class ClientActivity extends AppCompatActivity {

    public TextView mConsoleTextView;
    public ScrollView mScrollView;

    private static final String TAG = ClientActivity.class.getSimpleName();

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
            MyInitHandler handler = new MyInitHandler(this);
            int initReturn = OCMain.mainInit(handler);
            if (initReturn < 0) {
                Log.e(TAG, "Error in mainInit return code = " + initReturn);
            }
        }
    }

    @Override
    protected void onDestroy() {
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
}

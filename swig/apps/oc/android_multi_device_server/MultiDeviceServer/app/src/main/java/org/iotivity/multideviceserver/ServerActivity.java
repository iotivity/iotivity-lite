package org.iotivity.multideviceserver;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.ScrollView;
import android.widget.TextView;

import org.iotivity.oc.OcPlatform;
import org.iotivity.oc.OcUtils;

public class ServerActivity extends AppCompatActivity {

    private static final String TAG = ServerActivity.class.getSimpleName();

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

            // Note: If using a factory presets handler,
            // the factory presets handler must be set prior to calling systemInit().
            // The systemInit() function will cause the factory presets handler to
            // be called if it is set.
            OcUtils.setFactoryPresetsHandler(new FactoryPresetsHandler(this));

            ocPlatform = OcPlatform.getInstance();
            InitHandler handler = new InitHandler(this, ocPlatform);
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

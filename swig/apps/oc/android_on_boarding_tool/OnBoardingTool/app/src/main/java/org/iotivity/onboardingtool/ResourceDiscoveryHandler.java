package org.iotivity.onboardingtool;

import android.app.AlertDialog;
import android.app.Dialog;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

import org.iotivity.OCDiscoveryFlags;
import org.iotivity.OCDiscoveryAllHandler;
import org.iotivity.OCEndpoint;
import org.iotivity.OCMain;
import org.iotivity.OCUuidUtil;
import org.iotivity.oc.OcUtils;

import java.util.ArrayList;

public class ResourceDiscoveryHandler implements OCDiscoveryAllHandler {

    private static final String TAG = ResourceDiscoveryHandler.class.getSimpleName();

    private OnBoardingActivity activity;
    private ArrayAdapter<String> resourceAdapter;

    public ResourceDiscoveryHandler(OnBoardingActivity activity, ArrayAdapter<String> resourceAdapter) {
        this.activity = activity;
        this.resourceAdapter = resourceAdapter;
    }

    @Override
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMask, OCEndpoint endpoints,
            int resourcePropertiesMask, boolean more) {
        synchronized (resourceAdapter) {
            resourceAdapter.setNotifyOnChange(false);
            resourceAdapter.add(anchor + uri);
            resourceAdapter.setNotifyOnChange(true);
        }

        activity.runOnUiThread(new Runnable() {
            public void run() {
                resourceAdapter.notifyDataSetChanged();
            }
        });

        Log.d(TAG, "anchor: " + anchor + ", uri: " + uri);
        if(!more) {
            Log.d(TAG, "----End of discovery response---");
            return OCDiscoveryFlags.OC_STOP_DISCOVERY;
        }
        return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
    }
}

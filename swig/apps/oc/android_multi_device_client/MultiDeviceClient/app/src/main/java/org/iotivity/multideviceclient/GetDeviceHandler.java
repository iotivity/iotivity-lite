package org.iotivity.multideviceclient;

import android.util.Log;
import android.widget.Toast;

import org.iotivity.OCClientResponse;
import org.iotivity.OCEndpoint;
import org.iotivity.OCResponseHandler;
import org.iotivity.OCUuidUtil;
import org.iotivity.oc.OcCborException;
import org.iotivity.oc.OcRepresentation;
import org.iotivity.oc.OcUtils;

public class GetDeviceHandler implements OCResponseHandler {

    private static final String TAG = GetDeviceHandler.class.getSimpleName();

    private static final String N_KEY = "n";
    private static final String DI_KEY = "di";

    private MultiDeviceClientActivity activity;


    public GetDeviceHandler(MultiDeviceClientActivity activity) {
        this.activity = activity;
    }

    @Override
    public void handler(OCClientResponse response) {
        Log.d(TAG, "Get Device Name Handler:");
        OcRepresentation rep = new OcRepresentation(response.getPayload());
        String n = null;
        String di = null;
        while (rep != null) {
            try {
                if (N_KEY.equals(rep.getKey())) {
                    n = rep.getString(N_KEY);
                }
                if (DI_KEY.equals(rep.getKey())) {
                    di = rep.getString(DI_KEY);
                }
            } catch (OcCborException e) {
                Log.e(TAG, e.getMessage());
            }
            rep = rep.getNext();
        }

        if ((di != null) && (n != null)) {
            Log.d(TAG, "\tdi: " + di);
            Log.d(TAG, "\tn: " + n);
            OcfDeviceInfo deviceInfo = new OcfDeviceInfo(OCUuidUtil.stringToUuid(di), n);
            OCEndpoint ep = response.getEndpoint();
            while (ep != null) {
                String endpointStr = OcUtils.endpointToString(ep);
                Log.d(TAG, "\tendpoint: " + endpointStr);
                deviceInfo.addEndpoint(endpointStr);

                ep = ep.getNext();
            }

            Log.d(TAG, "discover resources at endpoint " + deviceInfo.getEndpoints()[0]);

            if (!OcUtils.doIPDiscoveryAllAtEndpoint(new ResourceDiscoveryAllHandler(deviceInfo), response.getEndpoint())) {
                final String msg = "Error issuing resource discovery all request for uuid " + di;
                Log.d(TAG, msg);
                activity.runOnUiThread(new Runnable() {
                    public void run() {
                        Toast.makeText(activity, msg, Toast.LENGTH_LONG).show();
                    }
                });
            }

            activity.addDevice(deviceInfo);
        }
    }
}

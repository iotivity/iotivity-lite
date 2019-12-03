package org.iotivity.multideviceserver;

import android.util.Log;

import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;

public class PutThermostatRequestHandler implements OCRequestHandler {

    private static final String TAG = PutThermostatRequestHandler.class.getSimpleName();

    private ServerActivity activity;
    private Thermostat thermostat;

    public PutThermostatRequestHandler(ServerActivity activity, Thermostat thermostat) {
        this.activity = activity;
        this.thermostat = thermostat;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        Log.d(TAG, "inside Put Thermostat Request Handler");
        new PostThermostatRequestHandler(activity, thermostat).handler(request, interfaces);
    }
}

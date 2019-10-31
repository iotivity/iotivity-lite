package org.iotivity.multideviceserver;

import android.util.Log;

import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCStatus;
import org.iotivity.oc.OcCborException;
import org.iotivity.oc.OcRepresentation;
import org.iotivity.oc.OcUtils;

public class PostThermostatRequestHandler implements OCRequestHandler {

    private static final String TAG = PostThermostatRequestHandler.class.getSimpleName();

    private ServerActivity activity;
    private Thermostat thermostat;

    public PostThermostatRequestHandler(ServerActivity activity, Thermostat thermostat) {
        this.activity = activity;
        this.thermostat = thermostat;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        Log.d(TAG, "inside Post Thermostat Request Handler");

        activity.msg("Post Thermostat:");

        OcRepresentation rep = new OcRepresentation(request.getRequestPayload());
        while (rep != null) {
            try {
                if (Thermostat.TEMPERATURE_KEY.equalsIgnoreCase(rep.getKey())) {
                    thermostat.setTemperature(rep.getDouble(Thermostat.TEMPERATURE_KEY));
                    activity.msg("\t\t" + Light.DIMMING_KEY + ": " + thermostat.getTemperature());
                }
            } catch (OcCborException e) {
                // ignore -- no temperature value
            }

            rep = rep.getNext();
        }

        activity.printLine();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

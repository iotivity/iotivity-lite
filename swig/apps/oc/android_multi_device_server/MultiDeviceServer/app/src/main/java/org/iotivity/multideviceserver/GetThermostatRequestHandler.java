package org.iotivity.multideviceserver;

import android.util.Log;

import org.iotivity.OCInterfaceMask;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCStatus;
import org.iotivity.oc.OcCborEncoder;
import org.iotivity.oc.OcUtils;

public class GetThermostatRequestHandler implements OCRequestHandler {

    private static final String TAG = GetThermostatRequestHandler.class.getSimpleName();

    private ServerActivity activity;
    private Thermostat thermostat;

    public GetThermostatRequestHandler(ServerActivity activity, Thermostat thermostat) {
        this.activity = activity;
        this.thermostat = thermostat;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        Log.d(TAG, "inside Get Thermostat Request Handler");

        activity.msg("Get Thermostat:");
        activity.msg("\t" + thermostat.getName() + ", " + thermostat.getTemperature());
        activity.printLine();

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        switch (interfaces) {
            case OCInterfaceMask.BASELINE: {
                root.processBaselineInterface(request.getResource());
                break;
            }
            case OCInterfaceMask.A:
            case OCInterfaceMask.S: {
                root.setDouble(Thermostat.TEMPERATURE_KEY, thermostat.getTemperature());
                break;
            }
            default:
                break;
        }
        root.done();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

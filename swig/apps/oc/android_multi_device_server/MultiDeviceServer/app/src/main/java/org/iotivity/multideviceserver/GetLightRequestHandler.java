package org.iotivity.multideviceserver;

import android.util.Log;

import org.iotivity.OCInterfaceMask;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCStatus;
import org.iotivity.oc.OcCborEncoder;
import org.iotivity.oc.OcUtils;

public class GetLightRequestHandler implements OCRequestHandler {

    private static final String TAG = GetLightRequestHandler.class.getSimpleName();

    private ServerActivity activity;
    private Light light;

    public GetLightRequestHandler(ServerActivity activity, Light light) {
        this.activity = activity;
        this.light = light;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        Log.d(TAG, "inside Get Light Request Handler");

        activity.msg("Get Light:");
        activity.msg("\t" + light.getName() + ", " + light.getDimming() + ", " + light.isOn());
        activity.printLine();

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        switch (interfaces) {
            case OCInterfaceMask.BASELINE: {
                root.processBaselineInterface(request.getResource());
                break;
            }
            case OCInterfaceMask.RW: {
                root.setBoolean(Light.SWITCH_KEY, light.isOn());
                root.setLong(Light.DIMMING_KEY, light.getDimming());
                break;
            }
            default:
                break;
        }
        root.done();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

package org.iotivity.multideviceserver;

import android.util.Log;

import org.iotivity.OCRepresentation;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCStatus;
import org.iotivity.oc.OcCborException;
import org.iotivity.oc.OcRepresentation;
import org.iotivity.oc.OcUtils;

public class PostLightRequestHandler implements OCRequestHandler {

    private static final String TAG = PostLightRequestHandler.class.getSimpleName();

    private ServerActivity activity;
    private Light light;

    public PostLightRequestHandler(ServerActivity activity, Light light) {
        this.activity = activity;
        this.light = light;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        Log.d(TAG, "inside Post Light Request Handler");

        activity.msg("Post Light:");

        OcRepresentation rep = new OcRepresentation(request.getRequestPayload());
        while (rep != null) {
            try {
                if (Light.SWITCH_KEY.equalsIgnoreCase(rep.getKey())) {
                    light.setOn(rep.getBoolean(Light.SWITCH_KEY));
                    activity.msg("\t\t" + Light.SWITCH_KEY + ": " + light.isOn());
                }
            } catch (OcCborException e) {
                // ignore -- no switch value
            }

            try {
                if (Light.DIMMING_KEY.equalsIgnoreCase(rep.getKey())) {
                    light.setDimming((int) rep.getLong(Light.DIMMING_KEY));
                    activity.msg("\t\t" + Light.DIMMING_KEY + ": " + light.getDimming());
                }
            } catch (OcCborException e) {
                // ignore -- no dimming value
            }

            rep = rep.getNext();
        }

        activity.printLine();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

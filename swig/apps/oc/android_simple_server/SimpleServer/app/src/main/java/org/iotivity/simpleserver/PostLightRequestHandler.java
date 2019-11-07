package org.iotivity.simpleserver;

import android.util.Log;

import org.iotivity.OCRepresentation;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCStatus;
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

        OCRepresentation rep = request.getRequestPayload();
        while (rep != null) {
            activity.msg("\tkey: " + rep.getName() + ", type: " + rep.getType());
            switch (rep.getType()) {
                case OC_REP_BOOL:
                    light.state = rep.getValue().getBool();
                    activity.msg("\t\tvalue: " + light.state);
                    break;
                case OC_REP_INT:
                    light.power = rep.getValue().getInteger();
                    activity.msg("\t\tvalue: " + light.power);
                    break;
                case OC_REP_STRING:
                    light.name = rep.getValue().getString();
                    activity.msg("\t\tvalue: " + light.name);
                    break;
                default:
                    activity.msg("NOT YET HANDLED VALUE");
                    OcUtils.sendResponse(request, OCStatus.OC_STATUS_BAD_REQUEST);
            }
            rep = rep.getNext();
        }

        activity.printLine();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

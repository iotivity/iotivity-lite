package org.iotivity.simpleclient;

import org.iotivity.CborEncoder;
import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCRepresentation;
import org.iotivity.OCResponseHandler;

public class GetLightResponseHandler implements OCResponseHandler {

    private static final String TAG = GetLightResponseHandler.class.getSimpleName();

    private ClientActivity activity;
    private Light light;

    public GetLightResponseHandler(ClientActivity activity, Light light) {
        this.activity = activity;
        this.light = light;
    }

    @Override
    public void handler(OCClientResponse response) {
        activity.msg("Get Light Response Handler:");
        OCRepresentation rep = response.getPayload();
        while (rep != null) {
            switch (rep.getType()) {
                case OC_REP_BOOL:
                    activity.msg("\tKey " + rep.getName() + " value " + rep.getValue().getBool());
                    light.state = rep.getValue().getBool();
                    break;
                case OC_REP_INT:
                    activity.msg("\tKey " + rep.getName() + " value " + rep.getValue().getInteger());
                    light.power = rep.getValue().getInteger();
                    break;
                case OC_REP_STRING:
                    activity.msg("\tKey " + rep.getName() + " value " + rep.getValue().getString());
                    light.name = rep.getValue().getString();
                    break;
                default:
                    break;
            }
            rep = rep.getNext();
        }
        activity.printLine();

        PutLightResponseHandler putLight = new PutLightResponseHandler(activity, light);
        if (OCMain.initPut(light.serverUri, light.serverEndpoint, null, putLight, OCQos.LOW_QOS)) {
            CborEncoder root = OCMain.repBeginRootObject();
            OCMain.repSetBoolean(root, "state", true);
            OCMain.repSetLong(root, "power", 15);
            OCMain.repEndRootObject();

            if (OCMain.doPut()) {
                activity.msg("\tSent PUT request");
            } else {
                activity.msg("\tCould no send PUT request");
            }
        } else {
            activity.msg("\tCould not init PUT request");
        }
        activity.printLine();
    }
}

package org.iotivity.simpleclient;

import org.iotivity.OCClientResponse;
import org.iotivity.OCRepresentation;
import org.iotivity.OCResponseHandler;

public class ObserveLightResponseHandler implements OCResponseHandler {

    private static final String TAG = ObserveLightResponseHandler.class.getSimpleName();

    private ClientActivity activity;
    private Light light;

    public ObserveLightResponseHandler(ClientActivity activity, Light light) {
        this.activity = activity;
        this.light = light;
    }

    @Override
    public void handler(OCClientResponse response) {
        activity.msg("OBSERVER Light:");
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
    }
}

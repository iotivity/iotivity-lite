package org.iotivity.simpleclient;

import org.iotivity.OCEventCallbackResult;
import org.iotivity.OCMain;
import org.iotivity.OCTriggerHandler;

public class StopObserveTriggerHandler implements OCTriggerHandler {

    private static final String TAG = StopObserveTriggerHandler.class.getSimpleName();

    private ClientActivity activity;

    public StopObserveTriggerHandler(ClientActivity activity) {
        this.activity = activity;
    }

    @Override
    public OCEventCallbackResult handler(Object userData) {
        Light light = (Light) userData;
        activity.msg("Stopping OBSERVE");
        activity.printLine();
        OCMain.stopObserve(light.serverUri, light.serverEndpoint);
        return OCEventCallbackResult.OC_EVENT_DONE;
    }
}

package org.iotivity.simpleclient;

import org.iotivity.OCEventCallbackResult;
import org.iotivity.OCMain;
import org.iotivity.OCTriggerHandler;

public class StopObserveTriggerHandler implements OCTriggerHandler {

    private static final String TAG = StopObserveTriggerHandler.class.getSimpleName();

    private ClientActivity activity;
    private Light light;

    public StopObserveTriggerHandler(ClientActivity activity, Light light) {
        this.activity = activity;
        this.light = light;
    }

    @Override
    public OCEventCallbackResult handler() {
        activity.msg("Stopping OBSERVE");
        activity.printLine();
        OCMain.stopObserve(light.serverUri, light.serverEndpoint);
        return OCEventCallbackResult.OC_EVENT_DONE;
    }
}

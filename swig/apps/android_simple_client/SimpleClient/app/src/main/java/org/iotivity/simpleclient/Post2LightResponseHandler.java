package org.iotivity.simpleclient;

import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCStatus;
import org.iotivity.OCResponseHandler;

public class Post2LightResponseHandler implements OCResponseHandler {

    private static final String TAG = Post2LightResponseHandler.class.getSimpleName();

    private ClientActivity activity;
    private Light light;

    public Post2LightResponseHandler(ClientActivity activity, Light light) {
        this.activity = activity;
        this.light = light;
    }

    @Override
    public void handler(OCClientResponse response) {
        activity.msg("POST2 light:");
        try {
            if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
                activity.msg("\tPOST2 response: CHANGED");
            } else if (response.getCode() == OCStatus.OC_STATUS_CREATED) {
                activity.msg("\tPOST2 response: CREATED");
            } else {
                activity.msg("\tPOST2 response code " + response.getCode().toString() + " (" + response.getCode() + ")");
            }
        } catch (IllegalArgumentException e) {
            activity.msg("\tError: Bad Response Code, Client not properly provisioned");
        }
        activity.printLine();

        ObserveLightResponseHandler observerLight = new ObserveLightResponseHandler(activity, light);
        OCMain.doObserve(light.serverUri, light.serverEndpoint, null, observerLight, OCQos.LOW_QOS);
        StopObserveTriggerHandler stopObserve = new StopObserveTriggerHandler(activity, light);
        OCMain.setDelayedHandler(stopObserve, 30);
        activity.msg("Sent OBSERVE request");
        activity.printLine();
    }
}

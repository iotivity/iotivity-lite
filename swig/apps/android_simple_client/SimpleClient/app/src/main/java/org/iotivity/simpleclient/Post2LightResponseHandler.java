package org.iotivity.simpleclient;

import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCStatus;
import org.iotivity.OCResponseHandler;

public class Post2LightResponseHandler implements OCResponseHandler {

    private static final String TAG = Post2LightResponseHandler.class.getSimpleName();

    private ClientActivity activity;

    public Post2LightResponseHandler(ClientActivity activity) {
        this.activity = activity;
    }

    @Override
    public void handler(OCClientResponse response) {
        Light light = (Light) response.getUser_data();
        activity.msg("POST2 light:");
        if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
            activity.msg("\tPUT response: CHANGED");
        } else if (response.getCode() == OCStatus.OC_STATUS_CREATED) {
            activity.msg("\tPUT response: CREATED");
        } else {
            activity.msg("\tPUT response code " + response.getCode().toString() + "(" + response.getCode() + ")");
        }
        activity.printLine();

        ObserveLightResponseHandler observerLight = new ObserveLightResponseHandler(activity);
        OCMain.doObserve(light.serverUri, light.serverEndpoint, null, observerLight, OCQos.LOW_QOS, light);
        StopObserveTriggerHandler stopObserve = new StopObserveTriggerHandler(activity);
        OCMain.setDelayedHandler(light, stopObserve, 30);
        activity.msg("Sent OBSERVE request");
        activity.printLine();
    }
}

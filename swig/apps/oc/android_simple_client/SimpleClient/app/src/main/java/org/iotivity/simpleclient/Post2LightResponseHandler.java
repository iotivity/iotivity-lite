package org.iotivity.simpleclient;

import org.iotivity.OCClientResponse;
import org.iotivity.OCQos;
import org.iotivity.OCResponseHandler;
import org.iotivity.OCStatus;
import org.iotivity.oc.OcUtils;

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
        if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
            activity.msg("\tPOST2 response: CHANGED");
        } else if (response.getCode() == OCStatus.OC_STATUS_CREATED) {
            activity.msg("\tPOST2 response: CREATED");
        } else {
            activity.msg("\tPOST2 response code " + response.getCode().toString() + " (" + response.getCode() + ")");
        }
        activity.printLine();

        ObserveLightResponseHandler observerLight = new ObserveLightResponseHandler(activity, light);
        OcUtils.doObserve(light.serverUri, light.serverEndpoint, null, observerLight, OCQos.LOW_QOS);
        StopObserveTriggerHandler stopObserve = new StopObserveTriggerHandler(activity, light);
        OcUtils.setDelayedHandler(stopObserve, 30);
        activity.msg("Sent OBSERVE request");
        activity.printLine();
    }
}

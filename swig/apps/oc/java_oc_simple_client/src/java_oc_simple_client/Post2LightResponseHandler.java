package java_oc_simple_client;

import org.iotivity.*;
import org.iotivity.oc.*;

public class Post2LightResponseHandler implements OCResponseHandler {

    private Light light;

    public Post2LightResponseHandler(Light light) {
        this.light = light;
    }

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("POST2 light:");
        try {
            if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
                System.out.println("\tPOST2 response: CHANGED");
            } else if (response.getCode() == OCStatus.OC_STATUS_CREATED) {
                System.out.println("\tPOST2 response: CREATED");
            } else {
                System.out.println(
                        "\tPOST2 response code " + response.getCode().toString() + " (" + response.getCode() + ")");
            }
        } catch (IllegalArgumentException e) {
            System.out.println("\tError: Bad Response Code, Client not properly provisioned");
        }

        ObserveLightResponseHandler observerLight = new ObserveLightResponseHandler(light);
        OcUtils.doObserve(light.getServerUri(), light.getServerEndpoint(), null, observerLight, OCQos.LOW_QOS);
        StopObserveTriggerHandler stopObserve = new StopObserveTriggerHandler(light);
        OcUtils.setDelayedHandler(stopObserve, 30);
        System.out.println("Sent OBSERVE request");
    }
}

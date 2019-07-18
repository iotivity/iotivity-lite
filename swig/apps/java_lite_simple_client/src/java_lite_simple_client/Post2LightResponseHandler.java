package java_lite_simple_client;

import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCStatus;
import org.iotivity.OCResponseHandler;

public class Post2LightResponseHandler implements OCResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("POST2 light:");
        try {
            if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
                System.out.println("\tPOST2 response: CHANGED");
            } else if (response.getCode() == OCStatus.OC_STATUS_CREATED) {
                System.out.println("\tPOST2 response: CREATED");
            } else {
                System.out.println("\tPOST2 response code " + response.getCode().toString() + " (" + response.getCode() + ")");
            }
        } catch (IllegalArgumentException e) {
            System.out.println("\tError: Bad Response Code, Client not properly provisioned");
        }

        ObserveLightResponseHandler observerLight = new ObserveLightResponseHandler();
        OCMain.doObserve(Light.serverUri, Light.serverEndpoint, null, observerLight, OCQos.LOW_QOS);
        StopObserveTriggerHandler stopObserve = new StopObserveTriggerHandler();
        OCMain.setDelayedHandler(stopObserve, 30);
        System.out.println("Sent OBSERVE request");
    }

}

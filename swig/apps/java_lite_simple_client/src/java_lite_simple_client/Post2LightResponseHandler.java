package java_lite_simple_client;

import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCStatus;
import org.iotivity.ResponseHandler;

public class Post2LightResponseHandler implements ResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("POST2 light:");
        if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
            System.out.println("\tPUT response: CHANGED");
        } else if (response.getCode() == OCStatus.OC_STATUS_CREATED) {
            System.out.println("\tPUT response: CREATED");
        } else {
            System.out.println("\tPUT response code " + response.getCode().toString() + "(" + response.getCode() + ")");
        }

        ObserveLightResponseHandler observerLight = new ObserveLightResponseHandler();
        OCMain.doObserve(Light.server_uri, Light.server, null, observerLight, OCQos.LOW_QOS, null);
        StopObserveTriggerHandler stopObserve = new StopObserveTriggerHandler();
        OCMain.setDelayedCallback(null, stopObserve, 30);
        System.out.println("Sent OBSERVE request");
    }

}

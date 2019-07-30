package java_oc_simple_client;

import org.iotivity.*;
import org.iotivity.oc.*;

public class PostLightCollectionResponseHandler implements OCResponseHandler {

    private OcfServer collection; // server object of a oic.wk.col

    public PostLightCollectionResponseHandler(OcfServer collection) {
        this.collection = collection;
    }

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("POST light collection:");
        if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
            System.out.println("\tPOST response: CHANGED");
        } else if (response.getCode() == OCStatus.OC_STATUS_CREATED) {
            System.out.println("\tPOST response: CREATED");
        } else {
            System.out
                    .println("\tPOST response code " + response.getCode().toString() + " (" + response.getCode() + ")");
        }

        ObserveLightCollectionResponseHandler responseHandler = new ObserveLightCollectionResponseHandler(collection);
        OcUtils.doGet(collection.getServerUri(), collection.getServerEndpoint(), "if=oic.if.b", responseHandler,
                OCQos.LOW_QOS);
        StopObserveCollectionTriggerHandler stopObserve = new StopObserveCollectionTriggerHandler(collection);
        OcUtils.setDelayedHandler(stopObserve, 30);
        System.out.println("Sent OBSERVE request");
    }
}

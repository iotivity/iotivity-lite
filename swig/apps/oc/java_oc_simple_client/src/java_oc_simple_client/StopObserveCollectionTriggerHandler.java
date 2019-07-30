package java_oc_simple_client;

import org.iotivity.*;
import org.iotivity.oc.*;

public class StopObserveCollectionTriggerHandler implements OCTriggerHandler {

    private OcfServer collection; // server object of a oic.wk.col

    public StopObserveCollectionTriggerHandler(OcfServer collection) {
        this.collection = collection;
    }

    @Override
    public OCEventCallbackResult handler() {
        System.out.println("-------------------------------------------------------");
        System.out.println("Stopping OBSERVE of Collection " + collection.getServerUri());
        System.out.println("-------------------------------------------------------");
        OcUtils.stopObserve(collection.getServerUri(), collection.getServerEndpoint());
        return OCEventCallbackResult.OC_EVENT_DONE;
    }
}

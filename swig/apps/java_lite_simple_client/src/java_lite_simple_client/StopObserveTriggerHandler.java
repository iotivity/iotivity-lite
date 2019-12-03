package java_lite_simple_client;

import org.iotivity.OCEventCallbackResult;
import org.iotivity.OCMain;
import org.iotivity.OCTriggerHandler;

public class StopObserveTriggerHandler implements OCTriggerHandler {

    @Override
    public OCEventCallbackResult handler() {
        System.out.println("-------------------------------------------------------");
        System.out.println("Stopping OBSERVE");
        System.out.println("-------------------------------------------------------");
        OCMain.stopObserve(Light.serverUri, Light.serverEndpoint);
        return OCEventCallbackResult.OC_EVENT_DONE;
    }

}

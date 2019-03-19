package java_oc_simple_client;

import org.iotivity.*;

public class StopObserveTriggerHandler implements OCTriggerHandler {

    private Light light;

    public StopObserveTriggerHandler(Light light) {
        this.light = light;
    }

    @Override
    public OCEventCallbackResult handler() {
        System.out.println("-------------------------------------------------------");
        System.out.println("Stopping OBSERVE");
        System.out.println("-------------------------------------------------------");
        OCMain.stopObserve(light.getServerUri(), light.getServerEndpoint());
        return OCEventCallbackResult.OC_EVENT_DONE;
    }
}

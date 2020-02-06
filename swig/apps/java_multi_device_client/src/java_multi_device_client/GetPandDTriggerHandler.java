package java_multi_device_client;

import org.iotivity.OCEventCallbackResult;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCTriggerHandler;

public class GetPandDTriggerHandler implements OCTriggerHandler {

    @Override
    public OCEventCallbackResult handler() {
        if(Fridge.serverEndpoint != null) {
            OCMain.doGet("oic/p", Fridge.serverEndpoint, null, new GetPlatformResponseHandler() , OCQos.LOW_QOS);
            OCMain.doGet("oic/d", Fridge.serverEndpoint, null, new GetDeviceResponseHandler(), OCQos.LOW_QOS);
        }
        if(Thermostat.serverEndpoint != null) {
            OCMain.doGet("oic/d", Thermostat.serverEndpoint, null, new GetDeviceResponseHandler(), OCQos.LOW_QOS);
        }
        Client.stopGetPost = true;
        return OCEventCallbackResult.OC_EVENT_DONE;
    }

}

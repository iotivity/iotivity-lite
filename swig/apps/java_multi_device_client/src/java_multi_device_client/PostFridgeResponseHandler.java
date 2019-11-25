package java_multi_device_client;

import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCStatus;
import org.iotivity.OCResponseHandler;

public class PostFridgeResponseHandler implements OCResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("POST fridge:");
        if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
            System.out.println("\tPOST response: CHANGED");
        } else if (response.getCode() == OCStatus.OC_STATUS_CREATED) {
            System.out.println("\tPOST response: CREATED");
        } else {
            System.out.println("\tPOST response code " + response.getCode().toString() + " (" + response.getCode().ordinal() + ")");
            Client.stopGetPost = true;
        }

        if (!Client.stopGetPost) {
            if (!OCMain.doGet(Fridge.serverUri, Fridge.serverEndpoint, null, Client.getFridgeResponseHandler, OCQos.LOW_QOS)) {
                System.out.println("\tCould not send GET request");
            }
        }
    }
}

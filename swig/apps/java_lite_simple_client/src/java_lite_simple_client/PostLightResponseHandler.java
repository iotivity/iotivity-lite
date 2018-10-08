package java_lite_simple_client;

import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCStatus;
import org.iotivity.OCResponseHandler;

public class PostLightResponseHandler implements OCResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("POST light:");
        if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
            System.out.println("\tPUT responce: CHANGED");
        } else if (response.getCode() == OCStatus.OC_STATUS_CREATED) {
            System.out.println("\tPUT responce: CREATED");
        } else {
            System.out.println("\tPUT response code " + response.getCode().toString() + "(" + response.getCode() + ")");
        }

        Post2LightResponseHandler postLight = new Post2LightResponseHandler();
        if (OCMain.initPost(Light.serverUri, Light.serverEndpoint, null, postLight, OCQos.LOW_QOS)) {
            OCMain.repStartRootObject();
            OCMain.repSetBoolean("state", true);
            OCMain.repSetInt("power", 55);
            OCMain.repEndRootObject();

            if (OCMain.doPost()) {
                System.out.println("\tSent POST request");
            } else {
                System.out.println("\tCould not send POST request");
            }
        } else {
            System.out.println("\tCould not init POST request");
        }
    }
}

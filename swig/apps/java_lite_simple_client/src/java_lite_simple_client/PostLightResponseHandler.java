package java_lite_simple_client;

import org.iotivity.CborEncoder;
import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCRep;
import org.iotivity.OCStatus;
import org.iotivity.OCResponseHandler;

public class PostLightResponseHandler implements OCResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("POST light:");
        if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
            System.out.println("\tPOST response: CHANGED");
        } else if (response.getCode() == OCStatus.OC_STATUS_CREATED) {
            System.out.println("\tPOST response: CREATED");
        } else {
            System.out.println("\tPOST response code " + response.getCode().toString() + " (" + response.getCode() + ")");
        }

        Post2LightResponseHandler postLight = new Post2LightResponseHandler();
        if (OCMain.initPost(Light.serverUri, Light.serverEndpoint, null, postLight, OCQos.LOW_QOS)) {
            CborEncoder root = OCRep.beginRootObject();
            OCRep.setBoolean(root, "value", true);
            OCRep.setLong(root, "dimmingSetting", 55);
            OCRep.endRootObject();

            if (OCMain.doPost()) {
                System.out.println("\tSent POST2 request");
            } else {
                System.out.println("\tCould not send POST2 request");
            }
        } else {
            System.out.println("\tCould not init POST2 request");
        }
    }
}

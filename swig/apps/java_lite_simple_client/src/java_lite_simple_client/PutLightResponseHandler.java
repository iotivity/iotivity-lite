package java_lite_simple_client;

import org.iotivity.CborEncoder;
import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCRep;
import org.iotivity.OCStatus;
import org.iotivity.OCResponseHandler;

public class PutLightResponseHandler implements OCResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("PUT light:");
        if ( response.getCode() == OCStatus.OC_STATUS_CHANGED) {
            System.out.println("\tPUT response: CHANGED");
        } else {
            System.out.println("\tPUT response code " + response.getCode().toString() + " (" + response.getCode() + ")");
        }

        PostLightResponseHandler postLight = new PostLightResponseHandler();
        if (OCMain.initPost(Light.serverUri, Light.serverEndpoint, null, postLight, OCQos.LOW_QOS)) {
            CborEncoder root = OCRep.beginRootObject();
            OCRep.setBoolean(root, "value", false);
            OCRep.setLong(root, "dimmingSetting", 105);
            OCRep.endRootObject();

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

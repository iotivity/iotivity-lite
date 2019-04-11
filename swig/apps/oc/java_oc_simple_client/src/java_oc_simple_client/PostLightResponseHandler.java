package java_oc_simple_client;

import org.iotivity.*;

public class PostLightResponseHandler implements OCResponseHandler {

    private Light light;

    public PostLightResponseHandler(Light light) {
        this.light = light;
    }

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("POST light:");
        if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
            System.out.println("\tPOST response: CHANGED");
        } else if (response.getCode() == OCStatus.OC_STATUS_CREATED) {
            System.out.println("\tPOST response: CREATED");
        } else {
            System.out
                    .println("\tPOST response code " + response.getCode().toString() + " (" + response.getCode() + ")");
        }

        Post2LightResponseHandler postLight = new Post2LightResponseHandler(light);
        if (OCMain.initPost(light.getServerUri(), light.getServerEndpoint(), null, postLight, OCQos.LOW_QOS)) {
            CborEncoder root = OCRep.beginRootObject();
            OCRep.setBoolean(root, "state", true);
            OCRep.setLong(root, "power", 55);
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

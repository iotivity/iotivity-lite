package java_oc_simple_client;

import org.iotivity.*;
import org.iotivity.oc.*;

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
        if (OcUtils.initPost(light.getServerUri(), light.getServerEndpoint(), null, postLight, OCQos.LOW_QOS)) {

            OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
            root.setBoolean("value", true);
            root.setLong("dimmingSetting", 55);
            root.done();

            if (OcUtils.doPost()) {
                System.out.println("\tSent POST2 request");
            } else {
                System.out.println("\tCould not send POST2 request");
            }
        } else {
            System.out.println("\tCould not init POST2 request");
        }
    }
}

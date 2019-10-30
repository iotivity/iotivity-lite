package java_oc_simple_client;

import org.iotivity.*;
import org.iotivity.oc.*;

public class PutLightResponseHandler implements OCResponseHandler {

    private Light light;

    public PutLightResponseHandler(Light light) {
        this.light = light;
    }

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("PUT light:");
        if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
            System.out.println("\tPUT response: CHANGED");
        } else {
            System.out
                    .println("\tPUT response code " + response.getCode().toString() + " (" + response.getCode() + ")");
        }

        PostLightResponseHandler postLight = new PostLightResponseHandler(light);
        if (OcUtils.initPost(light.getServerUri(), light.getServerEndpoint(), null, postLight, OCQos.LOW_QOS)) {

            OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
            root.setBoolean("value", false);
            root.setLong("dimmingSetting", 105);
            root.done();

            if (OcUtils.doPost()) {
                System.out.println("\tSent POST request");
            } else {
                System.out.println("\tCould not send POST request");
            }
        } else {
            System.out.println("\tCould not init POST request");
        }
    }
}

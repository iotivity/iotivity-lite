package java_oc_simple_client;

import org.iotivity.*;

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
        if (OCMain.initPost(light.getServerUri(), light.getServerEndpoint(), null, postLight, OCQos.LOW_QOS)) {
            CborEncoder root = OCMain.repBeginRootObject();
            OCMain.repSetBoolean(root, "state", false);
            OCMain.repSetLong(root, "power", 105);
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

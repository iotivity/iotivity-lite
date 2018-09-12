package java_lite_simple_client;

import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCStatus;
import org.iotivity.ResponseHandler;

public class PutLightResponseHandler implements ResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("PUT light:");
        if ( response.getCode() == OCStatus.OC_STATUS_CHANGED) {
            System.out.println("\tPUT response: CHANGED");
        } else {
            System.out.println("\tPUT response code " + response.getCode().toString() + "(" + response.getCode() + ")");
        }

        PostLightResponseHandler postLight = new PostLightResponseHandler();
        if (OCMain.initPost(Light.server_uri, Light.server, null, OCQos.LOW_QOS, postLight)) {
            OCMain.repStartRootObject();
            OCMain.repSetBoolean("state", false);
            OCMain.repSetInt("power", 105);
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

package java_lite_simple_client;

import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCResponseHandler;
import org.iotivity.OCStatus;

public class PostFridgeResponseHandler implements OCResponseHandler {

    private int looplimit;
    private GetFridgeResponseHandler fridgeHandler = new GetFridgeResponseHandler();

    PostFridgeResponseHandler() {
        looplimit = 0;
    }
    @Override
    public void handler(OCClientResponse response) {
        System.out.println("POST Fridge");
        if (response.getCode() == OCStatus.OC_STATUS_CHANGED) {
            System.out.println("POST response OK");
        } else {
            System.out.println("POST response code " + response.getCode());
        }
        
        if (looplimit < 20) {
            looplimit++;
            OCMain.doGet(Fridge.serverUri, Fridge.serverEndpoint, null, fridgeHandler, OCQos.LOW_QOS);
        }

    }

}

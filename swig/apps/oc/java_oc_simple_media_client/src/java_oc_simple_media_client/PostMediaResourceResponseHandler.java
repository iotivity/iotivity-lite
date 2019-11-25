package java_oc_simple_media_client;

import org.iotivity.*;
import org.iotivity.oc.*;

public class PostMediaResourceResponseHandler implements OCResponseHandler {

    private MediaResource mediaResource;

    public PostMediaResourceResponseHandler(MediaResource mediaResource) {
        this.mediaResource = mediaResource;
    }

    @Override
    public void handler(OCClientResponse response) {
        if ((response.getCode() == OCStatus.OC_STATUS_CHANGED) || (response.getCode() == OCStatus.OC_STATUS_CREATED)) {
            return;
        }
        // unexpected response
        System.out.println("\nPOST response code " + response.getCode().toString() + " (" + response.getCode() + ")");
    }
}

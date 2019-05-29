package java_oc_simple_media_client;

import org.iotivity.*;
import org.iotivity.oc.*;

public class PostMediaControlResourceResponseHandler implements OCResponseHandler {

    private MediaControlResource mediaControlResource;

    public PostMediaControlResourceResponseHandler(MediaControlResource mediaControlResource) {
        this.mediaControlResource = mediaControlResource;
    }

    @Override
    public void handler(OCClientResponse response) {
        if ((response.getCode() == OCStatus.OC_STATUS_CHANGED) || (response.getCode() == OCStatus.OC_STATUS_CREATED)) {
            new GetMediaControlResourceResponseHandler(mediaControlResource).handler(response);
            return;
        }
        // unexpected response
        System.out.println("\nPOST response code " + response.getCode().toString() + " (" + response.getCode() + ")");
    }
}

package java_oc_simple_media_client;

import org.iotivity.*;

public class ObserveMediaControlResourceResponseHandler implements OCResponseHandler {

    private MediaControlResource mediaControlResource;

    public ObserveMediaControlResourceResponseHandler(MediaControlResource mediaControlResource) {
        this.mediaControlResource = mediaControlResource;
    }

    @Override
    public void handler(OCClientResponse response) {
        new GetMediaControlResourceResponseHandler(mediaControlResource).handler(response);
        System.out.println(mediaControlResource.toString());
    }
}

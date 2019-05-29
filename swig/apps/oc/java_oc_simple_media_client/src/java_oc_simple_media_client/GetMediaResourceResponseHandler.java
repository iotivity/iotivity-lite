package java_oc_simple_media_client;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetMediaResourceResponseHandler implements OCResponseHandler {

    private static final String NAME_KEY = "name";
    private static final String URL_KEY = "url";

    private MediaResource mediaResource;

    public GetMediaResourceResponseHandler(MediaResource mediaResource) {
        this.mediaResource = mediaResource;
    }

    @Override
    public void handler(OCClientResponse response) {

        if (response.getPayload() != null) {
            OcRepresentation rep = new OcRepresentation(response.getPayload());
            while (rep != null) {
                try {
                    if (NAME_KEY.equalsIgnoreCase(rep.getKey())) {
                        mediaResource.setName(rep.getString(NAME_KEY));
                    }
                    if (URL_KEY.equalsIgnoreCase(rep.getKey())) {
                        mediaResource.setUrl(rep.getString(URL_KEY));
                    }
                } catch (OcCborException e) {
                    System.err.println(e.getMessage());
                }

                rep = rep.getNext();
            }

            // Post selection to the server
            PostMediaResourceResponseHandler postHandler = new PostMediaResourceResponseHandler(mediaResource);

            if (OcUtils.initPost(mediaResource.getServerUri(), mediaResource.getServerEndpoint(), null, postHandler,
                    OCQos.LOW_QOS)) {

                OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
                // no data
                root.done();

                if (OcUtils.doPost()) {
                    // successfully sent POST
                } else {
                    System.out.println("Could not send POST request");
                }
            } else {
                System.out.println("Could not init POST request");
            }
        }
    }
}

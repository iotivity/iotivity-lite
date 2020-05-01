package java_oc_channel_change_server;

import org.iotivity.*;

public class PutMediaInput implements OCRequestHandler {

    private MediaInput mediaInput;

    public PutMediaInput(MediaInput mediaInput) {
        this.mediaInput = mediaInput;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PutMediaInput RequestHandler");
        new PostMediaInput(mediaInput).handler(request, interfaces);
    }
}

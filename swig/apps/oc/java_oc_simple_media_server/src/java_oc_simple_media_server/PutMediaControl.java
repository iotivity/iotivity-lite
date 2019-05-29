package java_oc_simple_media_server;

import org.iotivity.*;

public class PutMediaControl implements OCRequestHandler {

    private MediaController controller;

    public PutMediaControl(MediaController controller) {
        this.controller = controller;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        // System.out.println("Inside the PutMediaControl RequestHandler");
        new PostMediaControl(controller).handler(request, interfaces);
    }
}

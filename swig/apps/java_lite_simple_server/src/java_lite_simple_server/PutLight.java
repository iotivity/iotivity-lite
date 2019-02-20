package java_lite_simple_server;

import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;

public class PutLight implements OCRequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PutLight RequestHandler");
        new PostLight().handler(request, interfaces);
    }
}

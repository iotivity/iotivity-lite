package java_multi_device_server;

import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;

public class PutLight implements OCRequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PutLight RequestHandler");
        new PostFridge().handler(request, interfaces);
    }
}

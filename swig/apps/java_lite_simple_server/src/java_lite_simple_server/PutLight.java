package java_lite_simple_server;

import org.iotivity.OCRequest;
import org.iotivity.RequestHandler;

public class PutLight implements RequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces, Object userData) {
        System.out.println("Inside the PutLight RequestHandler");
        new PostLight().handler(request, interfaces, userData);
        
    }

}

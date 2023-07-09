package java_dummy_bridge;

import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;

public class SwitchPutHandler implements OCRequestHandler {

    public SwitchPutHandler(VirtualLight light) {
        this.switchPostHandler = new SwitchPostHandler(light);
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the Put RequestHandler");
        switchPostHandler.handler(request, interfaces);
    }
    SwitchPostHandler switchPostHandler;
}

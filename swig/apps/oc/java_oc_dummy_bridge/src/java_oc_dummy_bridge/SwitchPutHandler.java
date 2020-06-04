package java_oc_dummy_bridge;

import org.iotivity.*;
import org.iotivity.oc.*;

public class SwitchPutHandler implements OCRequestHandler {

    private SwitchPostHandler switchPostHandler;
    
    public SwitchPutHandler(DummyVirtualLight light) {
        this.switchPostHandler = new SwitchPostHandler(light);
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the Put RequestHandler");
        switchPostHandler.handler(request, interfaces);
    }
}

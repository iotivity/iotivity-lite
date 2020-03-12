package java_smart_home_server;

import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;

public class PutSwitch implements OCRequestHandler {

    private Switch binarySwitch;

    public PutSwitch(Switch binarySwitch) {
        this.binarySwitch = binarySwitch;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PutSwitch RequestHandler");
        new PostSwitch(binarySwitch).handler(request, interfaces);
    }
}

package java_oc_simple_server;

import org.iotivity.*;

public class PutLight implements OCRequestHandler {

    private Light light;

    public PutLight(Light light) {
        this.light = light;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PutLight RequestHandler");
        new PostLight(light).handler(request, interfaces);
    }
}

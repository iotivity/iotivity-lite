package java_smart_home_server;

import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;

public class PutTemperature implements OCRequestHandler {

    private Temperature temperature;

    public PutTemperature(Temperature temperature) {
        this.temperature = temperature;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PutTemperature RequestHandler");
        new PostTemperature(temperature).handler(request, interfaces);
    }
}

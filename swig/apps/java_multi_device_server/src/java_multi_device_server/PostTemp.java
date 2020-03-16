package java_multi_device_server;

import org.iotivity.OCMain;
import org.iotivity.OCRepresentation;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCStatus;

public class PostTemp implements OCRequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PostTemp RequestHandler");
        System.out.println("POST temp:");
        OCRepresentation rep = request.getRequestPayload();
        while (rep != null) {
            System.out.println("-----------------------------------------------------");
            System.out.println("Key: " + rep.getName());
            System.out.println("Type: " + rep.getType());
            switch (rep.getType()) {
            case OC_REP_DOUBLE:
                if (rep.getName().equals("temperature")) {
                Thermostat.temperature = rep.getValue().getDouble();
                System.out.println("value: " + Thermostat.temperature);
                } else {
                    OCMain.sendResponse(request, OCStatus.OC_STATUS_BAD_REQUEST);
                }
                break;
            default:
                System.out.println("NOT YET HANDLED VALUE");
                OCMain.sendResponse(request, OCStatus.OC_STATUS_BAD_REQUEST);
            }
            System.out.println("-----------------------------------------------------");
            rep = rep.getNext();
        }
        OCMain.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

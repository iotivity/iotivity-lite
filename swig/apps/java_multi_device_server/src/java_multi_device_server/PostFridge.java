package java_multi_device_server;

import org.iotivity.OCMain;
import org.iotivity.OCRepresentation;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCStatus;

public class PostFridge implements OCRequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PostFridge RequestHandler");
        System.out.println("POST fridge:");
        OCRepresentation rep = request.getRequestPayload();
        while (rep != null) {
            System.out.println("-----------------------------------------------------");
            System.out.println("Key: " + rep.getName());
            System.out.println("Type: " + rep.getType());
            switch (rep.getType()) {
            case OC_REP_BOOL:
                if (rep.getName().equals("rapidFreeze")) {
                    Fridge.rapidFreeze = rep.getValue().getBool();
                    System.out.println("value: " + Fridge.rapidFreeze);
                }
                if (rep.getName().equals("rapidCool")) {
                    Fridge.rapidCool = rep.getValue().getBool();
                    System.out.println("value: " + Fridge.rapidCool);
                }
                if (rep.getName().equals("defrost")) {
                    Fridge.defrost = rep.getValue().getBool();
                    System.out.println("value: " + Fridge.defrost);
                }
                break;
            case OC_REP_INT:
                Fridge.filter = rep.getValue().getInteger();
                System.out.println("value: " + Fridge.filter);
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

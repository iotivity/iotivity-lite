package java_lite_simple_server;

import org.iotivity.CborEncoder;
import org.iotivity.OCMain;
import org.iotivity.OCRep;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCRepresentation;
import org.iotivity.OCStatus;

public class PostLight implements OCRequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PostLight RequestHandler");
        System.out.println("POST LIGHT:");
        OCRepresentation rep = request.getRequestPayload();
        while (rep != null) {
            System.out.println("-----------------------------------------------------");
            System.out.println("Key: " + rep.getName());
            System.out.println("Type: " + rep.getType());
            switch (rep.getType()) {
            case OC_REP_BOOL:
                Light.state = rep.getValue().getBool();
                System.out.println("value: " + Light.state);
                break;
            case OC_REP_INT:
                Light.power = rep.getValue().getInteger();
                System.out.println("value: " + Light.power);
                break;
            case OC_REP_STRING:
                Light.name = rep.getValue().getString();
                System.out.println("value: " + Light.name);
                break;
            default:
                System.out.println("NOT YET HANDLED VALUE");
                OCMain.sendResponse(request, OCStatus.OC_STATUS_BAD_REQUEST);
            }
            System.out.println("-----------------------------------------------------");
            rep = rep.getNext();
        }

        CborEncoder root = OCRep.beginRootObject();
        OCRep.setBoolean(root, "value", Light.state);
        OCRep.setLong(root, "dimmingSetting", Light.power);
        OCRep.endRootObject();

        OCMain.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

package java_lite_simple_server;

import org.iotivity.CborEncoder;
import org.iotivity.OCMain;
import org.iotivity.OCRep;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCRepresentation;
import org.iotivity.OCStatus;
import org.iotivity.OCType;

public class PostCounter implements OCRequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PostCounter RequestHandler");
        System.out.println("POST COUNTER:");
        OCRepresentation rep = request.getRequestPayload();
        while (rep != null) {
            System.out.println("-----------------------------------------------------");
            System.out.println("Key: " + rep.getName());
            System.out.println("Type: " + rep.getType());
            switch (rep.getType()) {
            case OC_REP_INT:
                Counter.count = rep.getValue().getInteger();
                System.out.println("value: " + Counter.count);
                break;
            case OC_REP_STRING:
                Counter.name = rep.getValue().getString();
                System.out.println("value: " + Counter.name);
                break;
            default:
                System.out.println("NOT YET HANDLED VALUE");
                OCMain.sendResponse(request, OCStatus.OC_STATUS_BAD_REQUEST);
            }
            System.out.println("-----------------------------------------------------");
            rep = rep.getNext();
        }

        CborEncoder root = OCRep.beginRootObject();
        OCRep.setLong(root, "count", Counter.count);
        OCRep.endRootObject();

        OCMain.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

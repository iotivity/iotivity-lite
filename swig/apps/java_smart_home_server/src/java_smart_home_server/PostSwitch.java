package java_smart_home_server;

import org.iotivity.CborEncoder;
import org.iotivity.OCMain;
import org.iotivity.OCRep;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCRepresentation;
import org.iotivity.OCStatus;

public class PostSwitch implements OCRequestHandler {

    private Switch binarySwitch;

    public PostSwitch(Switch binarySwitch) {
        this.binarySwitch = binarySwitch;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PostSwitch RequestHandler");
        System.out.println("POST SWITCH:");
        OCRepresentation rep = request.getRequestPayload();
        while (rep != null) {
            System.out.println("-----------------------------------------------------");
            System.out.println("Key: " + rep.getName());
            System.out.println("Type: " + rep.getType());
            switch (rep.getType()) {
            case OC_REP_BOOL:
                binarySwitch.setValue(rep.getValue().getBool());
                System.out.println("value: " + binarySwitch.getValue());
                break;
            case OC_REP_STRING:
                System.out.println("value: " + rep.getValue().getString());
                break;
            default:
                System.out.println("UNEXPECTED TYPE");
                OCMain.sendResponse(request, OCStatus.OC_STATUS_BAD_REQUEST);
            }
            System.out.println("-----------------------------------------------------");
            rep = rep.getNext();
        }

        CborEncoder root = OCRep.beginRootObject();
        OCRep.setBoolean(root, "value", binarySwitch.getValue());
        OCRep.endRootObject();

        OCMain.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

package java_lite_simple_server;

import org.iotivity.CborEncoder;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMain;
import org.iotivity.OCRep;
import org.iotivity.OCRequest;
import org.iotivity.OCStatus;
import org.iotivity.OCRequestHandler;

public class GetLight implements OCRequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the GetLight RequestHandler");
        Light.power++;
        System.out.println("GET LIGHT:");
        CborEncoder root = OCRep.beginRootObject();
        switch (interfaces) {
        case OCInterfaceMask.BASELINE: {
            OCMain.processBaselineInterface(request.getResource());
            /* fall through */
        }
        case OCInterfaceMask.RW: {
            OCRep.setBoolean(root, "value", Light.state);
            OCRep.setLong(root, "dimmingSetting", Light.power);
            OCRep.setTextString(root, "name", Light.name);
            break;
        }
        default:
            break;
        }
        OCRep.endRootObject();
        OCMain.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

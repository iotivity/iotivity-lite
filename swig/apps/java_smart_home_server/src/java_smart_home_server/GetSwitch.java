package java_smart_home_server;

import org.iotivity.CborEncoder;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMain;
import org.iotivity.OCRep;
import org.iotivity.OCRequest;
import org.iotivity.OCStatus;
import org.iotivity.OCRequestHandler;

public class GetSwitch implements OCRequestHandler {

    private Switch binarySwitch;

    public GetSwitch(Switch binarySwitch) {
        this.binarySwitch = binarySwitch;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the GetSwitch RequestHandler");
        System.out.println("GET SWITCH:");
        CborEncoder root = OCRep.beginRootObject();
        switch (interfaces) {
        case OCInterfaceMask.BASELINE: {
            OCMain.processBaselineInterface(request.getResource());
            /* fall through */
        }
        case OCInterfaceMask.A: {
            OCRep.setBoolean(root, "value", binarySwitch.getValue());
            break;
        }
        default:
            break;
        }
        OCRep.endRootObject();
        OCMain.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

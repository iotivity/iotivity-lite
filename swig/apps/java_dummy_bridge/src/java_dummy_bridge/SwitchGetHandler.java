package java_dummy_bridge;

import org.iotivity.CborEncoder;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMain;
import org.iotivity.OCRep;
import org.iotivity.OCRequest;
import org.iotivity.OCStatus;
import org.iotivity.OCRequestHandler;

public class SwitchGetHandler implements OCRequestHandler {

    SwitchGetHandler(VirtualLight light) {
        if (light == null) {
            throw new NullPointerException();
        }
        this.light = light;
    }
    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("GET LIGHT:");
        OCStatus response = OCStatus.OC_STATUS_OK;
        CborEncoder root = OCRep.beginRootObject();
        switch (interfaces) {
        case OCInterfaceMask.BASELINE: {
            OCMain.processBaselineInterface(request.getResource());
            /* fall through */
        }
        case OCInterfaceMask.A:
        case OCInterfaceMask.RW: {
            OCRep.setBoolean(root, "value", light.on);
            break;
        }
        default:
            response = OCStatus.OC_STATUS_BAD_REQUEST;
            break;
        }
        OCRep.endRootObject();
        OCMain.sendResponse(request, response);
    }
    
    private VirtualLight light;
}

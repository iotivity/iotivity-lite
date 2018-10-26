package java_lite_simple_server;

import org.iotivity.CborEncoder;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMain;
import org.iotivity.OCRequest;
import org.iotivity.OCStatus;
import org.iotivity.OCRequestHandler;

public class GetLight implements OCRequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces, Object userData) {
        System.out.println("Inside the GetLight RequestHandler");

        Light.power++;
        System.out.println("GET LIGHT:");
        CborEncoder root = OCMain.repBeginRootObject();
        switch(interfaces) {
        case OCInterfaceMask.BASELINE:
        {
            OCMain.processBaselineInterface(request.getResource());
            break;
        }
        case OCInterfaceMask.RW:
        {
            OCMain.repSetBoolean(root, "state", Light.state);
            OCMain.repSetInt(root, "power", Light.power);
            OCMain.repSetTextString(root, "name", Light.name);
            break;
        }
        default:
            break;
        }
        OCMain.repEndRootObject();
        OCMain.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

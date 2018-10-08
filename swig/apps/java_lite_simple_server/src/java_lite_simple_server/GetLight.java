package java_lite_simple_server;

import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMain;
import org.iotivity.OCRequest;
import org.iotivity.OCStatus;
import org.iotivity.RequestHandler;

public class GetLight implements RequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces, Object userData) {
        System.out.println("Inside the GetLight RequestHandler");

        Light.power++;
        System.out.println("GET LIGHT:");
        OCMain.repStartRootObject();
        switch(interfaces) {
        case OCInterfaceMask.BASELINE:
        {
            OCMain.processBaselineInterface(request.getResource());
            break;
        }
        case OCInterfaceMask.RW:
        {
            OCMain.repSetBoolean("state", Light.state);
            OCMain.repSetInt("power", Light.power);
            OCMain.repSetTextString("name", Light.name);
            break;
        }
        default:
            break;
        }
        OCMain.repEndRootObject();
        OCMain.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

package java_lite_simple_server;

import org.iotivity.CborEncoder;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMain;
import org.iotivity.OCRequest;
import org.iotivity.OCStatus;
import org.iotivity.OCRequestHandler;

public class GetCounter implements OCRequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the GetCounter RequestHandler");

        Counter.count++;
        System.out.println("GET COUNTER:");
        CborEncoder root = OCMain.repBeginRootObject();
        switch (interfaces) {
        case OCInterfaceMask.BASELINE: {
            OCMain.processBaselineInterface(request.getResource());
            /* fall through */
        }
        case OCInterfaceMask.R: {
            OCMain.repSetLong(root, "count", Counter.count);
            OCMain.repSetTextString(root, "name", Counter.name);
            break;
        }
        default:
            break;
        }
        OCMain.repEndRootObject();
        OCMain.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

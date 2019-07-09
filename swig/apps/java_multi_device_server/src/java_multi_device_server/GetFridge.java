package java_multi_device_server;

import org.iotivity.CborEncoder;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMain;
import org.iotivity.OCRep;
import org.iotivity.OCRequest;
import org.iotivity.OCStatus;
import org.iotivity.OCRequestHandler;

public class GetFridge implements OCRequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the GetFridge RequestHandler");
        System.out.println("GET fridge:");
        CborEncoder root = OCRep.beginRootObject();
        switch (interfaces) {
        case OCInterfaceMask.BASELINE: {
            OCMain.processBaselineInterface(request.getResource());
            /* fall through */
        }
        case OCInterfaceMask.A: {
            OCRep.setBoolean(root, "rapidFreeze", Fridge.rapidFreeze);
            OCRep.setBoolean(root, "defrost", Fridge.defrost);
            OCRep.setBoolean(root, "rapidCool", Fridge.rapidCool);
            OCRep.setLong(root, "filter", Fridge.filter);
            break;
        }
        default:
            break;
        }
        OCRep.endRootObject();
        OCMain.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

package java_oc_simple_server;

import org.iotivity.*;

public class GetLight implements OCRequestHandler {

    private Light light;

    public GetLight(Light light) {
        this.light = light;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the GetLight RequestHandler");

        light.setPower(light.getPower() + 1);
        System.out.println("GET LIGHT:");
        CborEncoder root = OCRep.beginRootObject();
        switch (interfaces) {
        case OCInterfaceMask.BASELINE:
            OCMain.processBaselineInterface(request.getResource());
            /* fall through */
        case OCInterfaceMask.RW:
            OCRep.setBoolean(root, "state", light.getState());
            OCRep.setLong(root, "power", light.getPower());
            OCRep.setTextString(root, "name", light.getName());
            break;
        default:
            break;
        }
        OCRep.endRootObject();
        OCMain.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

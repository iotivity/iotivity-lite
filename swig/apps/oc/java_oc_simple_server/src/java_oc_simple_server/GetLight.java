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
        CborEncoder root = OCMain.repBeginRootObject();
        switch (interfaces) {
        case OCInterfaceMask.BASELINE: {
            OCMain.processBaselineInterface(request.getResource());
            break;
        }
        case OCInterfaceMask.RW: {
            OCMain.repSetBoolean(root, "state", light.getState());
            OCMain.repSetLong(root, "power", light.getPower());
            OCMain.repSetTextString(root, "name", light.getName());
            break;
        }
        default:
            break;
        }
        OCMain.repEndRootObject();
        OCMain.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

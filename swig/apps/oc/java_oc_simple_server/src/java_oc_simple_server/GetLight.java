package java_oc_simple_server;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetLight implements OCRequestHandler {

    private Light light;

    public GetLight(Light light) {
        this.light = light;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the GetLight RequestHandler");

        light.setState(!light.getState());
        light.setPower(light.getPower() + 1);
        System.out.println("GET LIGHT:");
        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        switch (interfaces) {
        case OCInterfaceMask.BASELINE:
            root.processBaselineInterface(request.getResource());
            /* fall through */
        case OCInterfaceMask.RW:
            root.setBoolean("value", light.getState());
            root.setLong("dimmingSetting", light.getPower());
            root.setTextString("name", light.getName());
            break;
        default:
            break;
        }
        root.done();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

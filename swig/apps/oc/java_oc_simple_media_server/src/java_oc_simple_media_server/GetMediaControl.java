package java_oc_simple_media_server;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetMediaControl implements OCRequestHandler {

    private MediaController controller;

    public GetMediaControl(MediaController controller) {
        this.controller = controller;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        // System.out.println("Inside the GetMediaControl RequestHandler");

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        switch (interfaces) {
        case OCInterfaceMask.BASELINE:
            root.processBaselineInterface(request.getResource());
            /* fall through */
        case OCInterfaceMask.RW:
            root.setTextString("name", controller.getName());
            root.setBoolean("playstate", controller.getPlayState());
            root.setTextString("mediaaction", controller.getCurrentAction());
            root.setStringArray("mediaactions", controller.getAllowedActions());
            root.setDouble("mediaspeed", controller.getSpeed());
            root.setDouble("medialocation", controller.getLocation());
            break;
        default:
            break;
        }
        root.done();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

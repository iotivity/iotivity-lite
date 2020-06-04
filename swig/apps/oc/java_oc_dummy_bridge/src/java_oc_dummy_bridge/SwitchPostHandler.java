package java_oc_dummy_bridge;

import org.iotivity.*;
import org.iotivity.oc.*;

public class SwitchPostHandler implements OCRequestHandler {

    private DummyVirtualLight light;

    public SwitchPostHandler(DummyVirtualLight light) {
        if (light == null) {
            throw new IllegalArgumentException("DummyVirtualLight cannot be null");
        }
        this.light = light;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the Post BinarySwitch RequestHandler");
        System.out.println("POST BinarySwitch:");
        OCRepresentation rep = request.getRequestPayload();
        while (rep != null) {
            switch (rep.getType()) {
            case OC_REP_BOOL:
                light.setOn(rep.getValue().getBool());
                break;
            default:
                OCMain.sendResponse(request, OCStatus.OC_STATUS_BAD_REQUEST);
                break;
            }
            rep = rep.getNext();
        }

        if(DummyBridge.displayAsciiLightsUI) {
            DummyBridge.printAsciiLightsUI();
        }
        OCMain.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

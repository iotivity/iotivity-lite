package java_oc_dummy_bridge;

import org.iotivity.*;
import org.iotivity.oc.*;

public class SwitchGetHandler implements OCRequestHandler {

    private DummyVirtualLight light;

    SwitchGetHandler(DummyVirtualLight light) {
        if (light == null) {
            throw new IllegalArgumentException("DummyVirtualLight cannot be null");
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
            OCRep.setBoolean(root, "value", light.isOn());
            break;
        }
        default:
            response = OCStatus.OC_STATUS_BAD_REQUEST;
            break;
        }
        OCRep.endRootObject();
        OCMain.sendResponse(request, response);
    }
}

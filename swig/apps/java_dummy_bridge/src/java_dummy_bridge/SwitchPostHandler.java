package java_dummy_bridge;

import org.iotivity.OCMain;
import org.iotivity.OCRepresentation;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestHandler;
import org.iotivity.OCStatus;

public class SwitchPostHandler implements OCRequestHandler {

    public SwitchPostHandler(VirtualLight light) {
        if (light == null) {
            throw new NullPointerException();
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
                light.on = rep.getValue().getBool();
                break;
            default:
                OCMain.sendResponse(request, OCStatus.OC_STATUS_BAD_REQUEST);
                break;
            }
            rep = rep.getNext();
        }
        
        if(DummyBridgeMain.displayAsciiLightsUI) {
            DummyBridgeMain.printAsciiLightsUI();
        }
        OCMain.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
    
    private VirtualLight light;
}

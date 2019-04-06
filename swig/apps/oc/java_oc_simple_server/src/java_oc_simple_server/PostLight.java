package java_oc_simple_server;

import org.iotivity.*;

public class PostLight implements OCRequestHandler {

    private Light light;

    public PostLight(Light light) {
        this.light = light;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PostLight RequestHandler");
        System.out.println("POST LIGHT:");
        OCRepresentation rep = request.getRequest_payload();
        while (rep != null) {
            System.out.println("-----------------------------------------------------");
            System.out.println("Key: " + rep.getName());
            System.out.println("Type: " + rep.getType());
            switch (rep.getType()) {
            case OC_REP_BOOL:
                light.setState(rep.getValue().getBool());
                System.out.println("value: " + light.getState());
                break;
            case OC_REP_INT:
                light.setPower(rep.getValue().getInteger());
                System.out.println("value: " + light.getPower());
                break;
            case OC_REP_STRING:
                light.setName(rep.getValue().getString());
                System.out.println("value: " + light.getName());
                break;
            default:
                System.out.println("NOT YET HANDLED VALUE");
                OCMain.sendResponse(request, OCStatus.OC_STATUS_BAD_REQUEST);
            }
            System.out.println("-----------------------------------------------------");
            rep = rep.getNext();
        }

        CborEncoder root = OCMain.repBeginRootObject();
        OCMain.repSetBoolean(root, "state", light.getState());
        OCMain.repSetLong(root, "power", light.getPower());
        OCMain.repEndRootObject();

        OCMain.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

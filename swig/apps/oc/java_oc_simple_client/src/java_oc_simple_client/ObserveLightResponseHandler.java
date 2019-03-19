package java_oc_simple_client;

import org.iotivity.*;

public class ObserveLightResponseHandler implements OCResponseHandler {

    private Light light;

    public ObserveLightResponseHandler(Light light) {
        this.light = light;
    }

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("OBSERVER Light:");
        OCRepresentation rep = response.getPayload();
        while (rep != null) {
            switch (rep.getType()) {
            case OC_REP_BOOL:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getBool());
                light.setState(rep.getValue().getBool());
                break;
            case OC_REP_INT:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getInteger());
                light.setPower(rep.getValue().getInteger());
                break;
            case OC_REP_STRING:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getString());
                light.setName(rep.getValue().getString());
                break;
            default:
                break;
            }
            rep = rep.getNext();
        }
    }
}

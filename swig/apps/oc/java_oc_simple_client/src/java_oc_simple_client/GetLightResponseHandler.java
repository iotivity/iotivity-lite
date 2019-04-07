package java_oc_simple_client;

import org.iotivity.*;

public class GetLightResponseHandler implements OCResponseHandler {

    private Light light;

    public GetLightResponseHandler(Light light) {
        this.light = light;
    }

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("Get Light Response Handler:");
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

        PutLightResponseHandler putLight = new PutLightResponseHandler(light);
        if (OCMain.initPut(light.getServerUri(), light.getServerEndpoint(), null, putLight, OCQos.LOW_QOS)) {
            CborEncoder root = OCMain.repBeginRootObject();
            OCMain.repSetBoolean(root, "state", true);
            OCMain.repSetLong(root, "power", 15);
            OCMain.repEndRootObject();

            if (OCMain.doPut()) {
                System.out.println("\tSent PUT request");
            } else {
                System.out.println("\tCould not send PUT request");
            }
        } else {
            System.out.println("\tCould not init PUT request");
        }
    }
}

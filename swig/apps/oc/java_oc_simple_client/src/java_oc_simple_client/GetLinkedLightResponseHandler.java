package java_oc_simple_client;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetLinkedLightResponseHandler implements OCResponseHandler {

    private Light light;

    public GetLinkedLightResponseHandler(Light light) {
        this.light = light;
    }

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("Get Linked Light Response Handler:");
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

        PostLinkedLightResponseHandler putLight = new PostLinkedLightResponseHandler(light);
        if (OcUtils.initPut(light.getServerUri(), light.getServerEndpoint(), null, putLight, OCQos.LOW_QOS)) {

            OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
            root.setBoolean("value", !light.getState());
            root.setLong("dimmingSetting", light.getPower() + 1);
            root.done();

            if (OcUtils.doPut()) {
                System.out.println("\tSent PUT request");
            } else {
                System.out.println("\tCould not send PUT request");
            }
        } else {
            System.out.println("\tCould not init PUT request");
        }
    }
}

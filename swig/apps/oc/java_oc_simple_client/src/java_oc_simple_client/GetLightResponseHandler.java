package java_oc_simple_client;

import org.iotivity.*;
import org.iotivity.oc.*;

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
        if (OcUtils.initPut(light.getServerUri(), light.getServerEndpoint(), null, putLight, OCQos.LOW_QOS)) {

            OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
            root.setBoolean("value", true);
            root.setLong("dimmingSetting", 15);
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

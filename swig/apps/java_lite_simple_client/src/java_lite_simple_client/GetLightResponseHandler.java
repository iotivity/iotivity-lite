package java_lite_simple_client;

import org.iotivity.CborEncoder;
import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCRep;
import org.iotivity.OCRepresentation;
import org.iotivity.OCResponseHandler;
import org.iotivity.OCType;

public class GetLightResponseHandler implements OCResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("Get Light Response Handler:");
        OCRepresentation rep = response.getPayload();
        while(rep != null) {
            switch(rep.getType()) {
            case OC_REP_BOOL:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getBool());
                Light.state =  rep.getValue().getBool();
                break;
            case OC_REP_INT:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getInteger());
                Light.power =  rep.getValue().getInteger();
                break;
            case OC_REP_STRING:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getString());
                Light.name =  rep.getValue().getString();
                break;
            default:
                break;
            }
            rep = rep.getNext();
        }

        PutLightResponseHandler putLight = new PutLightResponseHandler();
        if (OCMain.initPut(Light.serverUri, Light.serverEndpoint, null, putLight, OCQos.LOW_QOS)) {
            CborEncoder root = OCRep.beginRootObject();
            OCRep.setBoolean(root, "value", true);
            OCRep.setLong(root, "dimmingSetting", 15);
            OCRep.endRootObject();

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

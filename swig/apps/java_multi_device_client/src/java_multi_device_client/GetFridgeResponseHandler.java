package java_multi_device_client;

import org.iotivity.CborEncoder;
import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCRep;
import org.iotivity.OCRepresentation;
import org.iotivity.OCResponseHandler;

public class GetFridgeResponseHandler implements OCResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("Get Fridge:");
        OCRepresentation rep = response.getPayload();
        while(rep != null) {
            switch(rep.getType()) {
            case OC_REP_BOOL:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getBool());
                if (rep.getName().equals("rapidFreeze")) {
                    Fridge.rapidFreeze = rep.getValue().getBool();
                } else if (rep.getName().equals("rapidCool")) {
                    Fridge.rapidCool = rep.getValue().getBool();
                } else if (rep.getName().equals("defrost")) {
                    Fridge.defrost = rep.getValue().getBool();
                }
                break;
            case OC_REP_INT:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getInteger());
                if (rep.getName().equals("filter")) {
                }
                break;
            default:
                break;
            }
            rep = rep.getNext();
        }

        if (!Client.stopGetPost && OCMain.initPost(Fridge.serverUri, Fridge.serverEndpoint, null, Client.postFridge, OCQos.LOW_QOS)) {
            CborEncoder root = OCRep.beginRootObject();
            OCRep.setLong(root, "filter", Fridge.filter + 5);
            OCRep.setBoolean(root, "rapidFreeze", !Fridge.rapidFreeze);
            OCRep.setBoolean(root, "defrost", !Fridge.defrost);
            OCRep.setBoolean(root, "rapidCool", !Fridge.rapidCool);
            OCRep.endRootObject();
            if (OCMain.doPost()) {
                System.out.println("\tSent POST request");
            } else {
                System.out.println("\tCould not send POST request");
            }
        } else {
            System.out.println("\tCould not init POST request");
        }
    }
}

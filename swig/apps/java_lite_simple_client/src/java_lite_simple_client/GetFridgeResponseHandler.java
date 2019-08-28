package java_lite_simple_client;


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
        System.out.println("GET fridge:");
        OCRepresentation rep = response.getPayload();
        while (rep != null) {
            //System.out.println("key: " + rep.getName());
            switch(rep.getType()) {
            case OC_REP_BOOL:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getBool());
                if (rep.getName().equals("rapidFreeze")) {
                    Fridge.rapidFreeze = rep.getValue().getBool();
                }
                if (rep.getName().equals("rapidCool")) {
                    Fridge.rapidCool = rep.getValue().getBool();
                }
                if (rep.getName().equals("defrost")) {
                    Fridge.defrost = rep.getValue().getBool();
                }
                break;
            case OC_REP_INT:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getInteger());
                if(rep.getName().equals("filter")) {
                    Fridge.filter = rep.getValue().getInteger();
                }
                break;
            default:
                break;
            }
            rep = rep.getNext();
        }
        
        PostFridgeResponseHandler postFridge = new PostFridgeResponseHandler();
        if (/* TODO add stop post state */ OCMain.initPost(Fridge.serverUri, Fridge.serverEndpoint, null, postFridge, OCQos.LOW_QOS)) {
            CborEncoder root = OCRep.beginRootObject();
            OCRep.setLong(root, "filter", Fridge.filter + 5);
            OCRep.setBoolean(root, "rapidFreeze", !Fridge.rapidFreeze);
            OCRep.setBoolean(root, "rapidCool", !Fridge.rapidCool);
            OCRep.setBoolean(root, "defrost", !Fridge.defrost);
            OCRep.endRootObject();
            if(OCMain.doPost()) {
                System.out.println("Sent POST request");
            } else {
                System.out.println("Could not send POST");
            }
        } else {
            System.out.println("Could not init POST");
        }
    }
}

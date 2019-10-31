package java_multi_device_client;

import org.iotivity.OCClientResponse;
import org.iotivity.OCRep;
import org.iotivity.OCRepresentation;
import org.iotivity.OCResponseHandler;

public class GetDeviceResponseHandler implements OCResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("Get Device:");
        OCRepresentation rep = response.getPayload();
        while(rep != null) {
            switch(rep.getType()) {
            case OC_REP_STRING:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getString());
                break;
            case OC_REP_STRING_ARRAY:
                System.out.println("\tKey " + rep.getName() + " value " + OCRep.ocArrayToStringArray(rep.getValue().getArray()));
                break;
            default:
                break;
            }
            rep = rep.getNext();
        }
    }
}

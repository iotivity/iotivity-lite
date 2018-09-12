package java_lite_simple_server_windows;

import org.iotivity.OCClientResponse;
import org.iotivity.OCRequestPayload;
import org.iotivity.ResponseHandler;

public class ObserveLightResponseHandler implements ResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("OBSERVER Light:");
        OCRequestPayload rep = response.getPayload();
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
    }

}

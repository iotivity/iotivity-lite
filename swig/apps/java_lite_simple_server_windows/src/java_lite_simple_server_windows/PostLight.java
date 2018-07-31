package java_lite_simple_server_windows;

import org.iotivity.OCMain;
import org.iotivity.OCRequest;
import org.iotivity.OCRequestPayload;
import org.iotivity.OCStatus;
import org.iotivity.RequestHandler;

public class PostLight implements RequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces, Object user_data) {
        System.out.println("Inside the PostLight RequestHandler");
        System.out.println("POST LIGHT:");
        OCRequestPayload rep = request.getRequest_payload();
        while(rep != null) {
            System.out.println("-----------------------------------------------------");
            System.out.println("Key: " + rep.getName());
            System.out.println("Type: " + rep.getType());
            switch(rep.getType()) {
            case OC_REP_BOOL:
                Light.state = rep.getValue().get_boolean();
                System.out.println("value: " + Light.state);
                break;
            case OC_REP_INT:
                Light.power = rep.getValue().getInteger();
                System.out.println("value: " + Light.power);
                break;
            case OC_REP_STRING:
                Light.name = rep.getValue().getString();
                System.out.println("value: " + Light.name);
                break;
            default:
                System.out.println("NOT YET HANDLED VALUE");
                OCMain.sendResponce(request, OCStatus.OC_STATUS_BAD_REQUEST);
            }
        
            System.out.println("-----------------------------------------------------");
            rep = rep.getNext();
        }
        OCMain.sendResponce(request, OCStatus.OC_STATUS_CHANGED);
    }

}

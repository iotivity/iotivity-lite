package java_lite_simple_server_windows;

import org.iotivity.OCRequest;
import org.iotivity.OCRequestPayload;
import org.iotivity.RequestHandler;

public class PostLight implements RequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces, Object user_data) {
        System.out.println("Inside the PostLight RequestHandler");
        System.out.println("POST LIGHT:");
        OCRequestPayload rep = request.getRequest_payload();
//        while(rep != null) {
//            System.out.println("key: " + rep.getName());
//        }
    }

}

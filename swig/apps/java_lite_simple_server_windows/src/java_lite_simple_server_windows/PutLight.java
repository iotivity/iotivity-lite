package java_lite_simple_server_windows;

import org.iotivity.OCRequest;
import org.iotivity.RequestHandler;

public class PutLight implements RequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces, Object user_data) {
        System.out.println("Inside the PutLight RequestHandler");
        new PostLight().handler(request, interfaces, user_data);
    }

}

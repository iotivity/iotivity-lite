package java_lite_simple_server_windows;

import org.iotivity.OCInterfaceMask;
import org.iotivity.OCRequest;
import org.iotivity.OCStatus;
import org.iotivity.RequestHandler;
import org.iotivity.api;

public class GetLight implements RequestHandler {

    @Override
    public void handler(OCRequest request, int interfaces, Object userData) {
        System.out.println("Inside the GetLight RequestHandler");
        Light.power++;
        System.out.println("GET LIGHT:");
        api.rep_start_root_object();
        switch(interfaces) {
        case OCInterfaceMask.BASELINE:
        {
            api.process_baseline_interface(request.getResource());
            break;
        }
        case OCInterfaceMask.RW:
        {
            api.rep_set_boolean("state", Light.state);
            api.rep_set_int("power", Light.power);
            api.rep_set_text_string("name", Light.name);
            break;
        }
        default: 
            break;
        }
        api.rep_end_root_object();
        api.send_responce(request, OCStatus.OC_STATUS_OK);
    }
}

package java_oc_simple_server;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetCounter implements OCRequestHandler {

    private Counter counter;

    public GetCounter(Counter counter) {
        this.counter = counter;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the GetCounter RequestHandler");

        counter.setCounter(counter.getCounter() + 1);
        System.out.println("GET COUNTER:");
        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        switch (interfaces) {
        case OCInterfaceMask.BASELINE:
            root.processBaselineInterface(request.getResource());
            /* fall through */
        case OCInterfaceMask.R:
            root.setLong("count", counter.getCounter());
            root.setTextString("name", counter.getName());
            break;
        default:
            break;
        }
        root.done();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

package java_oc_simple_server;

import org.iotivity.*;

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
        CborEncoder root = OCRep.beginRootObject();
        switch (interfaces) {
        case OCInterfaceMask.BASELINE:
            OCMain.processBaselineInterface(request.getResource());
            /* fall through */
        case OCInterfaceMask.R:
            OCRep.setLong(root, "count", counter.getCounter());
            OCRep.setTextString(root, "name", counter.getName());
            break;
        default:
            break;
        }
        OCRep.endRootObject();
        OCMain.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

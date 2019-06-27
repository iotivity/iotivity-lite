package java_oc_simple_server;

import org.iotivity.*;
import org.iotivity.oc.*;

public class PostCounter implements OCRequestHandler {

    private Counter counter;

    public PostCounter(Counter counter) {
        this.counter = counter;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PostCounter RequestHandler");
        System.out.println("POST COUNTER:");
        OCRepresentation rep = request.getRequestPayload();
        while (rep != null) {
            System.out.println("-----------------------------------------------------");
            System.out.println("Key: " + rep.getName());
            System.out.println("Type: " + rep.getType());
            switch (rep.getType()) {
            case OC_REP_INT:
                counter.setCounter(rep.getValue().getInteger());
                System.out.println("value: " + counter.getCounter());
                break;
            case OC_REP_STRING:
                counter.setName(rep.getValue().getString());
                System.out.println("value: " + counter.getName());
                break;
            default:
                System.out.println("NOT YET HANDLED VALUE");
                OcUtils.sendResponse(request, OCStatus.OC_STATUS_BAD_REQUEST);
            }
            System.out.println("-----------------------------------------------------");
            rep = rep.getNext();
        }

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        root.setLong("count", counter.getCounter());
        root.done();

        OcUtils.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

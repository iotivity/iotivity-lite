package java_oc_simple_server;

import org.iotivity.*;

public class PostCounter implements OCRequestHandler {

    private Counter counter;

    public PostCounter(Counter counter) {
        this.counter = counter;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PostCounter RequestHandler");
        System.out.println("POST COUNTER:");
        OCRepresentation rep = request.getRequest_payload();
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
                OCMain.sendResponse(request, OCStatus.OC_STATUS_BAD_REQUEST);
            }
            System.out.println("-----------------------------------------------------");
            rep = rep.getNext();
        }

        CborEncoder root = OCMain.repBeginRootObject();
        OCMain.repSetLong(root, "count", counter.getCounter());
        OCMain.repEndRootObject();

        OCMain.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

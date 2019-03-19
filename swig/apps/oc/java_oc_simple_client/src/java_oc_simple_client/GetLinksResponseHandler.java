package java_oc_simple_client;

import org.iotivity.*;

public class GetLinksResponseHandler implements OCResponseHandler {

    private OcfServer server;

    public GetLinksResponseHandler(OcfServer server) {
        this.server = server;
    }

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("Get Links Response Handler:");
        OCRepresentation ll = response.getPayload();
        while (ll != null) {
            switch (ll.getType()) {
            case OC_REP_OBJECT:
                OCRepresentation link = ll.getValue().getObject();
                while (link != null) {
                    switch (link.getType()) {
                    case OC_REP_STRING:
                        System.out.println("\tKey " + link.getName() + " value " + link.getValue().getString());
                        break;
                    case OC_REP_STRING_ARRAY:
                        String[] strings = OCMain.ocArrayToStringArray(link.getValue().getArray());
                        StringBuilder msg = new StringBuilder("[");
                        for (String s : strings) {
                            msg.append(" " + s);
                        }
                        msg.append(" ]");
                        System.out.println("\tKey " + link.getName() + " value " + msg);
                        break;
                    case OC_REP_OBJECT:
                        System.out.println("\tKey " + link.getName() + " value " + link.getValue().getObject());
                        OCRepresentation obj = link.getValue().getObject();
                        while (obj != null) {
                            switch (obj.getType()) {
                            case OC_REP_STRING:
                                System.out.println("\t\tKey " + obj.getName() + " value " + obj.getValue().getString());
                                break;
                            case OC_REP_INT:
                                System.out
                                        .println("\t\tKey " + obj.getName() + " value " + obj.getValue().getInteger());
                                break;
                            case OC_REP_BOOL:
                                System.out.println("\t\tKey " + obj.getName() + " value " + obj.getValue().getBool());
                                break;
                            default:
                                break;
                            }
                            obj = obj.getNext();
                        }
                        break;
                    default:
                        break;
                    }
                    link = link.getNext();
                }
                break;
            default:
                break;
            }
            ll = ll.getNext();
        }
    }
}

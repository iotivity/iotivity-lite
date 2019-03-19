package java_oc_simple_client;

import org.iotivity.*;

public class GetLightCollectionResponseHandler implements OCResponseHandler {

    private OcfServer collection; // server object of a oic.wk.col

    public GetLightCollectionResponseHandler(OcfServer collection) {
        this.collection = collection;
    }

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("Get Light Collection Response Handler:");
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
                    case OC_REP_STRING_ARRAY: {
                        String[] strings = OCMain.ocArrayToStringArray(link.getValue().getArray());
                        StringBuilder msg = new StringBuilder("[");
                        for (String s : strings) {
                            msg.append(" " + s);
                        }
                        msg.append(" ]");
                        System.out.println("\tKey " + link.getName() + " value " + msg);
                        break;
                    }
                    case OC_REP_OBJECT: {
                        StringBuilder msg = new StringBuilder("\t { ");
                        OCRepresentation obj = link.getValue().getObject();
                        while (obj != null) {
                            msg.append("{");
                            switch (obj.getType()) {
                            case OC_REP_STRING:
                                msg.append(" " + obj.getName() + ": " + obj.getValue().getString());
                                break;
                            case OC_REP_INT:
                                msg.append(" " + obj.getName() + ": " + obj.getValue().getInteger());
                                break;
                            case OC_REP_BOOL:
                                msg.append(" " + obj.getName() + ": " + obj.getValue().getBool());
                                break;
                            default:
                                break;
                            }
                            msg.append(" } ");
                            obj = obj.getNext();
                        }
                        msg.append("}");
                        System.out.println(msg);
                        break;
                    }
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

        PostLightCollectionResponseHandler responseHandler = new PostLightCollectionResponseHandler(collection);
        if (OCMain.initPost(collection.getServerUri(), collection.getServerEndpoint(), "if=oic.if.b", responseHandler,
                OCQos.LOW_QOS)) {

            CborEncoder links = OCMain.repBeginLinksArray();

            CborEncoder link = OCMain.repObjectArrayBeginItem(links);
            OCMain.repSetTextString(link, "href", "/light/1");
            CborEncoder light = OCMain.repOpenObject(link, "rep");
            OCMain.repSetLong(light, "power", 10);
            OCMain.repSetBoolean(light, "state", true);
            OCMain.repCloseObject(link, light);
            OCMain.repObjectArrayEndItem(links, link);

            link = OCMain.repObjectArrayBeginItem(links);
            OCMain.repSetTextString(link, "href", "/light/2");
            light = OCMain.repOpenObject(link, "rep");
            OCMain.repSetLong(light, "power", 20);
            OCMain.repSetBoolean(light, "state", true);
            OCMain.repCloseObject(link, light);
            OCMain.repObjectArrayEndItem(links, link);

            OCMain.repEndLinksArray();

            if (OCMain.doPost()) {
                System.out.println("\tSent POST request");
            } else {
                System.out.println("\tCould not send POST request");
            }
        } else {
            System.out.println("\tCould not init POST request");
        }
    }
}

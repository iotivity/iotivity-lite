package java_oc_simple_client;

import org.iotivity.*;
import org.iotivity.oc.*;

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
                        String[] strings = OcUtils.ocArrayToStringArray(link.getValue().getArray());
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
        if (OcUtils.initPost(collection.getServerUri(), collection.getServerEndpoint(), "if=oic.if.b", responseHandler,
                OCQos.LOW_QOS)) {

            OcCborEncoder links = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.LINKS_ARRAY);

            OcCborEncoder link = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ARRAY_ITEM, links);
            link.setTextString("href", "/light/1");
            OcCborEncoder light = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.OBJECT, link, "rep");
            light.setLong("dimmingSetting", 10);
            light.setBoolean("value", true);
            light.done();
            link.done();

            link = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ARRAY_ITEM, links);
            link.setTextString("href", "/light/2");
            light = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.OBJECT, link, "rep");
            light.setLong("dimmingSetting", 20);
            light.setBoolean("value", false);
            light.done();
            link.done();

            links.done();

            if (OcUtils.doPost()) {
                System.out.println("\tSent POST request");
            } else {
                System.out.println("\tCould not send POST request");
            }
        } else {
            System.out.println("\tCould not init POST request");
        }
    }
}

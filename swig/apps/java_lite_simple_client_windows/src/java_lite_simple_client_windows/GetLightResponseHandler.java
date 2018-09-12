package java_lite_simple_client_windows;

import org.iotivity.OCClientResponse;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCRequestPayload;
import org.iotivity.OCType;
import org.iotivity.ResponseHandler;

public class GetLightResponseHandler implements ResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("Get Light Response Handler:");
        OCRequestPayload rep = response.getPayload();
        while(rep != null) {
            switch(rep.getType()) {
            case OC_REP_BOOL:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getBool());
                Light.state =  rep.getValue().getBool();
                break;
            case OC_REP_INT:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getInteger());
                Light.power =  rep.getValue().getInteger();
                break;
            case OC_REP_STRING:
                System.out.println("\tKey " + rep.getName() + " value " + rep.getValue().getString());
                Light.name =  rep.getValue().getString();
                break;
            default:
                break;
            }
            rep = rep.getNext();
        }

        PutLightResponseHandler putLight = new PutLightResponseHandler();
        if (OCMain.initPut(Light.server_uri, Light.server, null, OCQos.LOW_QOS, putLight)) {
            OCMain.repStartRootObject();
            OCMain.repSetBoolean("state", true);
            OCMain.repSetInt("power", 15);
            OCMain.repEndRootObject();
            
            if (OCMain.doPut()) {
                System.out.println("\tSent PUT request");
            } else {
                System.out.println("\tCould no send PUT request");
            }
        } else {
            System.out.println("\tCould not init PUT request");
        }

    }

}

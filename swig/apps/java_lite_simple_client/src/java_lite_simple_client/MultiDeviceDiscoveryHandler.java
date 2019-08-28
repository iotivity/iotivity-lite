package java_lite_simple_client;

import org.iotivity.OCClientResponse;
import org.iotivity.OCDiscoveryFlags;
import org.iotivity.OCDiscoveryHandler;
import org.iotivity.OCEndpoint;
import org.iotivity.OCEndpointUtil;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCResponseHandler;

public class MultiDeviceDiscoveryHandler implements OCDiscoveryHandler {

    GetFridgeResponseHandler fridgeHandler = new GetFridgeResponseHandler();

    @Override
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMask, OCEndpoint endpoint,
            int resourcePropertiesMask) {
        for (String type : types ) {
            if (type.equals("oic.r.refrigeration")) {
                Fridge.serverUri = uri;
                Fridge.serverEndpoint = endpoint;

                System.out.println("The " + type + " resource " + uri + " hosted in device " + anchor + "at endpoints:");
                OCEndpoint ep = endpoint;
                while (ep != null) {
                    System.out.println("\t" + OCEndpointUtil.toString(ep));
                    ep = ep.getNext();
                }
                OCMain.doGet(Fridge.serverUri, Fridge.serverEndpoint, null, fridgeHandler, OCQos.LOW_QOS);
            } else if (type.equals("oic.r.temperature")) {
                Thermostat.serverUri = uri;
                Thermostat.serverEndpoint = endpoint;

                System.out.println("the " + type + " resource " + uri + " hosted in device " + anchor + "at endpoints:");
                OCEndpoint ep = endpoint;
                while (ep != null) {
                    System.out.println("\t" +OCEndpointUtil.toString(ep));
                    ep = ep.getNext();
                }
                //add do get
            } else {
                OCMain.freeServerEndpoints(endpoint);
            }
            return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
        }
        OCMain.freeServerEndpoints(endpoint);
        return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
    }

}

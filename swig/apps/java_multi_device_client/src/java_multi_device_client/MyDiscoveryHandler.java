package java_multi_device_client;


import org.iotivity.OCDiscoveryHandler;
import org.iotivity.OCDiscoveryFlags;
import org.iotivity.OCEndpoint;
import org.iotivity.OCEndpointUtil;
import org.iotivity.OCMain;
import org.iotivity.OCQos;

public class MyDiscoveryHandler implements OCDiscoveryHandler {

    @Override
    public OCDiscoveryFlags handler(String anchor,
                                    String uri,
                                    String[] types,
                                    int interfaceMask,
                                    OCEndpoint endpoints,
                                    int resourcePropertiesMask) {
        for (String type : types) {
            if (type.equals("oic.r.refrigeration")) {
                Fridge.serverUri = uri;
                Fridge.serverEndpoint = endpoints;
                System.out.println("Refrigeration resource " + uri + " hosted in device " + anchor + " at endpoints:");
                OCEndpoint ep = endpoints;
                while(ep != null) {
                    System.out.println("\t" + OCEndpointUtil.toString(ep));
                    ep = ep.getNext();
                }
                OCMain.doGet(Fridge.serverUri, Fridge.serverEndpoint, null, Client.getFridgeResponseHandler, OCQos.LOW_QOS);
                return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
            } else if (type.equals("oic.r.temperature")) {
                Thermostat.serverUri = uri;
                Thermostat.serverEndpoint = OCEndpointUtil.listCopy(endpoints);

                System.out.println("Temperature resource " + uri + " hosted in device " + anchor + " at endpoints:");
                OCEndpoint ep = endpoints;
                while(ep != null) {
                    System.out.println("\t" + OCEndpointUtil.toString(ep));
                    ep = ep.getNext();
                }
                GetTemperatureResponseHandler responseHandler = new GetTemperatureResponseHandler();
                OCMain.doGet(Thermostat.serverUri, Thermostat.serverEndpoint, null, responseHandler, OCQos.LOW_QOS);
                return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
            }
        }
        return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
    }
}

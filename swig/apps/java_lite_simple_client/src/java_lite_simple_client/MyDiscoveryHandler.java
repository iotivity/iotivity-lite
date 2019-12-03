package java_lite_simple_client;

import java.util.Arrays;

import org.iotivity.OCDiscoveryHandler;
import org.iotivity.OCDiscoveryFlags;
import org.iotivity.OCEndpoint;
import org.iotivity.OCEndpointUtil;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCResourcePropertiesMask;

public class MyDiscoveryHandler implements OCDiscoveryHandler {

    @Override
    public OCDiscoveryFlags handler(String anchor,
                                    String uri,
                                    String[] types,
                                    int interfaceMask,
                                    OCEndpoint endpoint,
                                    int resourcePropertiesMask) {
        System.out.println("DiscoveryHandler");
        System.out.println("\tanchor: " + anchor);
        System.out.println("\turi: " + uri);
        System.out.println("\ttypes: " + Arrays.toString(types));

        String interfaces_found = "";
        if ((interfaceMask & OCInterfaceMask.S) > 0) {
            interfaces_found += "S";
        }
        if ((interfaceMask & OCInterfaceMask.A) > 0) {
            if(!interfaces_found.isEmpty()) {
                interfaces_found += " | ";
            }
            interfaces_found += "A";
        }
        if ((interfaceMask & OCInterfaceMask.RW) > 0) {
            if(!interfaces_found.isEmpty()) {
                interfaces_found += " | ";
            }
            interfaces_found += "RW";
        }
        if ((interfaceMask & OCInterfaceMask.R) > 0) {
            if(!interfaces_found.isEmpty()) {
                interfaces_found += " | ";
            }
            interfaces_found += "R";
        }
        if ((interfaceMask & OCInterfaceMask.B) > 0) {
            if(!interfaces_found.isEmpty()) {
                interfaces_found += " | ";
            }
            interfaces_found += "B";
        }
        if ((interfaceMask & OCInterfaceMask.LL) > 0) {
            if(!interfaces_found.isEmpty()) {
                interfaces_found += " | ";
            }
            interfaces_found += "LL";
        }
        if ((interfaceMask & OCInterfaceMask.BASELINE) > 0) {
            if(!interfaces_found.isEmpty()) {
                interfaces_found += " | ";
            }
            interfaces_found += "BASELINE";
        }
        System.out.println("\tinterfaces: " + interfaces_found);

        String properties_found = "";
        if ((resourcePropertiesMask & OCResourcePropertiesMask.OC_PERIODIC) > 0) {
            properties_found += "PERIODIC";
        }
        if ((resourcePropertiesMask & OCResourcePropertiesMask.OC_SECURE) > 0) {
            if(!properties_found.isEmpty()) {
                properties_found += " | ";
            }
            properties_found += "SECURE";
        }
        if ((resourcePropertiesMask & OCResourcePropertiesMask.OC_OBSERVABLE) > 0) {
            if(!properties_found.isEmpty()) {
                properties_found += " | ";
            }
            properties_found += "OBSERVABLE";
        }
        if ((resourcePropertiesMask & OCResourcePropertiesMask.OC_DISCOVERABLE) > 0) {
            if(!properties_found.isEmpty()) {
                properties_found += " | ";
            }
            properties_found += "DISCOVERABLE";
        }
        System.out.println("\tresource properties: " + properties_found);

        for (String type: types) {
            if(type.equals("oic.r.switch.binary")) {
                Light.serverEndpoint = OCEndpointUtil.listCopy(endpoint);
                Light.serverUri = uri;
                System.out.println("\tResource " + Light.serverUri + " hosted at endpoint(s):");
                OCEndpoint ep = endpoint;
                while (ep != null) {
                    String endpointStr = OCEndpointUtil.toString(ep);
                    System.out.println("\t\tendpoint: " + endpointStr);
                    System.out.println("\t\t\tendpoint.device " + ep.getDevice());
                    System.out.println("\t\t\tendpoint.flags " + ep.getFlags());
                    System.out.println("\t\t\tendpoint.interfaceIndex " + ep.getInterfaceIndex());
                    System.out.println("\t\t\tendpoint.version " + ep.getVersion().toString());
                    ep = ep.getNext();
                }
                GetLightResponseHandler responseHandler = new GetLightResponseHandler();
                OCMain.doGet(Light.serverUri, Light.serverEndpoint, null, responseHandler, OCQos.LOW_QOS);
                return OCDiscoveryFlags.OC_STOP_DISCOVERY;
            }
        }
        return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
    }
}

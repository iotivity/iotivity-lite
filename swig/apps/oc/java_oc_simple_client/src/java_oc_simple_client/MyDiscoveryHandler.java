package java_oc_simple_client;

import java.util.Arrays;

import org.iotivity.*;
import org.iotivity.oc.*;

public class MyDiscoveryHandler implements OCDiscoveryHandler {

    @Override
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMask, OCEndpoint endpoint,
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
            if (!interfaces_found.isEmpty()) {
                interfaces_found += " | ";
            }
            interfaces_found += "A";
        }
        if ((interfaceMask & OCInterfaceMask.RW) > 0) {
            if (!interfaces_found.isEmpty()) {
                interfaces_found += " | ";
            }
            interfaces_found += "RW";
        }
        if ((interfaceMask & OCInterfaceMask.R) > 0) {
            if (!interfaces_found.isEmpty()) {
                interfaces_found += " | ";
            }
            interfaces_found += "R";
        }
        if ((interfaceMask & OCInterfaceMask.B) > 0) {
            if (!interfaces_found.isEmpty()) {
                interfaces_found += " | ";
            }
            interfaces_found += "B";
        }
        if ((interfaceMask & OCInterfaceMask.LL) > 0) {
            if (!interfaces_found.isEmpty()) {
                interfaces_found += " | ";
            }
            interfaces_found += "LL";
        }
        if ((interfaceMask & OCInterfaceMask.BASELINE) > 0) {
            if (!interfaces_found.isEmpty()) {
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
            if (!properties_found.isEmpty()) {
                properties_found += " | ";
            }
            properties_found += "SECURE";
        }
        if ((resourcePropertiesMask & OCResourcePropertiesMask.OC_OBSERVABLE) > 0) {
            if (!properties_found.isEmpty()) {
                properties_found += " | ";
            }
            properties_found += "OBSERVABLE";
        }
        if ((resourcePropertiesMask & OCResourcePropertiesMask.OC_DISCOVERABLE) > 0) {
            if (!properties_found.isEmpty()) {
                properties_found += " | ";
            }
            properties_found += "DISCOVERABLE";
        }
        System.out.println("\tresource properties: " + properties_found);

        for (String type : types) {
            if (type.equals("oic.r.switch.binary") || type.equals("oic.wk.col")) {
                StringBuilder msg = new StringBuilder();
                OcfServer server;
                if (type.equals("oic.r.switch.binary")) {
                    server = new Light();
                } else {
                    server = new OcfServer();
                }

                server.setServerEndpoint(endpoint);
                server.setServerUri(uri);
                msg.append("\tResource " + server.getServerUri() + " hosted at endpoint(s):\n");
                OCEndpoint ep = endpoint;
                while (ep != null) {
                    String endpointStr = OcUtils.endpointToString(ep);
                    msg.append("\t\tendpoint: " + endpointStr + "\n");
                    msg.append("\t\t\tendpoint.device " + ep.getDevice() + "\n");
                    msg.append("\t\t\tendpoint.flags " + ep.getFlags() + "\n");
                    msg.append("\t\t\tendpoint.interfaceIndex " + ep.getInterfaceIndex() + "\n");
                    msg.append("\t\t\tendpoint.version " + ep.getVersion().toString() + "\n");
                    ep = ep.getNext();
                }
                System.out.print(msg);

                if (server instanceof Light) {
                    GetLightResponseHandler responseHandler = new GetLightResponseHandler((Light) server);
                    OcUtils.doGet(server.getServerUri(), server.getServerEndpoint(), null, responseHandler,
                            OCQos.LOW_QOS);
                } else {
                    GetLinksResponseHandler responseHandler = new GetLinksResponseHandler(server);
                    OcUtils.doGet(server.getServerUri(), server.getServerEndpoint(), "if=oic.if.ll", responseHandler,
                            OCQos.LOW_QOS);
                }

                return OCDiscoveryFlags.OC_STOP_DISCOVERY;
            }
        }
        return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
    }
}

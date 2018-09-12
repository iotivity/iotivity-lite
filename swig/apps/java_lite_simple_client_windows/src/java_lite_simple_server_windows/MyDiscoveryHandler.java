package java_lite_simple_server_windows;

import java.util.Arrays;

import org.iotivity.DiscoveryHandler;
import org.iotivity.OCDiscoveryFlags;
import org.iotivity.OCEndpoint;
import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMain;
import org.iotivity.OCQos;
import org.iotivity.OCTransportFlags;

public class MyDiscoveryHandler implements DiscoveryHandler {

    @Override
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaces, OCEndpoint endpoint,
            int bm, Object userData) {
        System.out.println("...........................................................");
        System.out.println("...........................................................");
        System.out.println("...........................................................");
        System.out.println("...........................................................");
        System.out.println("...........................................................");
        System.out.println("\tinterfaces: " + interfaces);
        System.out.println("\tendpoint: " + endpoint);
        System.out.println("\tbm: " + bm);
        System.out.println("\tuserData: " + userData);
        System.out.println("...........................................................");
        System.out.println("...........................................................");
        System.out.println("...........................................................");
        System.out.println("...........................................................");
        System.out.println("...........................................................");
        System.out.println("...........................................................");

        System.out.println("DiscoveryHandler");
        System.out.println("\tanchor: " + anchor);
        System.out.println("\turi: " + uri);
        System.out.println("\ttypes: " + Arrays.toString(types));
        for (String type: types) {
            if(type.equals("core.light")) {
                Light.server = endpoint;
                Light.server_uri = uri;
                System.out.println("Resource " + Light.server_uri + " hosted at endpoints:");
                System.out.println("\tendpoint.device " + endpoint.getDevice());
                System.out.println("\tendpoint.flags " + endpoint.getFlags());
                System.out.println("\tendpoint.interfaceIndex " + endpoint.getInterfaceIndex());
                // TODO can not print endpoint.getVersion() do to value not being set
                //System.out.println("\tendpoint.version " + endpoint.getVersion().ordinal());
                OCEndpoint ep = endpoint;
                while (ep != null) {
                    if ((ep.getFlags() & OCTransportFlags.IPV4) > 0) {
                        System.out.println("[" + ep.getAddr().getIpv4().getAddress()[0] + "." +
                                ep.getAddr().getIpv4().getAddress()[1] + "." +
                                ep.getAddr().getIpv4().getAddress()[2] + "." +
                                ep.getAddr().getIpv4().getAddress()[3] + "]:" +
                                ep.getAddr().getIpv4().getPort());
                    } else if ((ep.getFlags() & OCTransportFlags.IPV6) > 0) {
                        System.out.println(String.format("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                                                       + "%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%d",
                                                       ep.getAddr().getIpv6().getAddress()[0],
                                                       ep.getAddr().getIpv6().getAddress()[1],
                                                       ep.getAddr().getIpv6().getAddress()[2],
                                                       ep.getAddr().getIpv6().getAddress()[3],
                                                       ep.getAddr().getIpv6().getAddress()[4],
                                                       ep.getAddr().getIpv6().getAddress()[5],
                                                       ep.getAddr().getIpv6().getAddress()[6],
                                                       ep.getAddr().getIpv6().getAddress()[7],
                                                       ep.getAddr().getIpv6().getAddress()[8],
                                                       ep.getAddr().getIpv6().getAddress()[9],
                                                       ep.getAddr().getIpv6().getAddress()[10],
                                                       ep.getAddr().getIpv6().getAddress()[11],
                                                       ep.getAddr().getIpv6().getAddress()[12],
                                                       ep.getAddr().getIpv6().getAddress()[13],
                                                       ep.getAddr().getIpv6().getAddress()[14],
                                                       ep.getAddr().getIpv6().getAddress()[15],
                                                       ep.getAddr().getIpv6().getPort()
                                                       ));
                    }
                    ep = ep.getNext();
                }
                GetLightResponseHandler responseHandler = new GetLightResponseHandler();
                OCMain.doGet(Light.server_uri, Light.server, null, OCQos.LOW_QOS, responseHandler);
                return OCDiscoveryFlags.OC_STOP_DISCOVERY;
            }
        }
        OCMain.freeServerEndpoints(endpoint);
        return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
    }

}

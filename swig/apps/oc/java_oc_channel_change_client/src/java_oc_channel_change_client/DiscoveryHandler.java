package java_oc_channel_change_client;

import java.util.Set;

import org.iotivity.*;
import org.iotivity.oc.*;

public class DiscoveryHandler implements OCDiscoveryHandler {

    private Set<OcfServerResource> serverResources;

    public DiscoveryHandler(Set<OcfServerResource> serverResources) {
        this.serverResources = serverResources;
    }

    @Override
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMask, OCEndpoint endpoint,
            int resourcePropertiesMask) {
        // System.out.println("DiscoveryHandler");
        // System.out.println("\tanchor: " + anchor);
        // System.out.println("\turi: " + uri);

        for (String type : types) {
            OcfServerResource serverResource = null;
            if (type.equals("oic.r.channelchange")) {
                serverResource = new ChannelChangeResource();
            } else {
                serverResource = new OcfServerResource();
            }

            if (serverResource != null) {
                serverResource.setServerEndpoint(endpoint);
                serverResource.setServerUri(uri);
                serverResources.add(serverResource);
                return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
            }
        }
        return OCDiscoveryFlags.OC_STOP_DISCOVERY;
    }
}

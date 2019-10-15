package java_onboarding_tool;

import org.iotivity.OCDiscoveryFlags;
import org.iotivity.OCDiscoveryHandler;
import org.iotivity.OCEndpoint;
import org.iotivity.OCMain;

public class ResourceDiscovery implements OCDiscoveryHandler {

    @Override
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMask, OCEndpoint endpoints,
            int resourcePropertiesMask) {
        System.out.println("anchor " + anchor + ", uri : " + uri);
        OCMain.freeServerEndpoints(endpoints);
        return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
    }
}

package java_onboarding_tool;

import org.iotivity.OCDiscoveryAllHandler;
import org.iotivity.OCDiscoveryFlags;
import org.iotivity.OCEndpoint;

public class ResourceDiscovery implements OCDiscoveryAllHandler {

    @Override
    public OCDiscoveryFlags handler(String anchor, String uri, String[] types, int interfaceMask, OCEndpoint endpoints,
            int resourcePropertiesMask, boolean more) {
        System.out.println("anchor " + anchor + ", uri : " + uri);
        if(!more) {
            System.out.println("----End of discovery response---");
            return OCDiscoveryFlags.OC_STOP_DISCOVERY;
        }
        return OCDiscoveryFlags.OC_CONTINUE_DISCOVERY;
    }
}

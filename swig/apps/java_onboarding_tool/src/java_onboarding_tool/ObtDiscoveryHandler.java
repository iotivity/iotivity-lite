package java_onboarding_tool;

import org.iotivity.OCEndpoint;
import org.iotivity.OCObtDiscoveryHandler;
import org.iotivity.OCUuidType;

public class ObtDiscoveryHandler implements OCObtDiscoveryHandler {

    @Override
    public int handler(OCUuidType uuid, OCEndpoint endpoint, Object userData) {

        return 0;
    }

}

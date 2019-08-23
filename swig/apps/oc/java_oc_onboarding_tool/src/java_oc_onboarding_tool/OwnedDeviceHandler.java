package java_oc_onboarding_tool;

import org.iotivity.*;
import org.iotivity.oc.*;

public class OwnedDeviceHandler implements OCObtDiscoveryHandler {

    @Override
    public void handler(OCUuid uuid, OCEndpoint[] endpoints) {
        String deviceId = OCUuidUtil.uuidToString(uuid);
        System.out.println("\nDiscovered owned device: " + deviceId + " at:");
        for (OCEndpoint endpoint : endpoints) {
            String endpointStr = OcUtils.endpointToString(endpoint);
            System.out.println(endpointStr);
        }

        OcUtils.doGet("/oic/d", endpoints[0], null, new GetOwnedDeviceNameHandler(), OCQos.LOW_QOS);
    }
}

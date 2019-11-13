package java_oc_onboarding_tool;

import org.iotivity.*;
import org.iotivity.oc.*;

public class OwnedDeviceHandler implements OCObtDiscoveryHandler {

    @Override
    public void handler(OCUuid uuid, OCEndpoint endpoints) {
        OCEndpoint ep = endpoints;
        String deviceId = OCUuidUtil.uuidToString(uuid);
        System.out.println("\nDiscovered owned device: " + deviceId + " at:");
        while (endpoints != null) {
            String endpointStr = OcUtils.endpointToString(endpoints);
            System.out.println(endpointStr);
            endpoints = endpoints.getNext();
        }

        OcUtils.doGet("/oic/d", ep, null, new GetOwnedDeviceNameHandler(), OCQos.HIGH_QOS);
    }
}

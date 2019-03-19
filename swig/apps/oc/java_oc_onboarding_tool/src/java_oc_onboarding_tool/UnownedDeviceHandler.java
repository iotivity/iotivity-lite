package java_oc_onboarding_tool;

import org.iotivity.*;
import org.iotivity.oc.*;

public class UnownedDeviceHandler implements OCObtDiscoveryHandler {

    @Override
    public void handler(OCUuid uuid, OCEndpoint endpoints) {
        String deviceId = OCUuidUtil.uuidToString(uuid);
        System.out.println("\nDiscovered unowned device: " + deviceId + " at:");
        while (endpoints != null) {
            String[] endpointStr = new String[1];
            OCMain.endpointToString(endpoints, endpointStr);
            System.out.println(endpointStr[0]);
            endpoints = endpoints.getNext();
        }

        ObtMain.unownedDevices.add(uuid);
    }
}

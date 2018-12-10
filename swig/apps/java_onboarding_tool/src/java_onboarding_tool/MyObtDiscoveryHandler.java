package java_onboarding_tool;

import org.iotivity.OCEndpoint;
import org.iotivity.OCMain;
import org.iotivity.OCObtDiscoveryHandler;
import org.iotivity.OCUuid;
import org.iotivity.OCUuidType;

public class MyObtDiscoveryHandler implements OCObtDiscoveryHandler {

    @Override
    public void handler(OCUuidType uuid, OCEndpoint endpoints, Object userData) {
        String deviceId = OCUuid.uuidToString(uuid);
        System.out.println("\nDiscovered unowned device: "+ deviceId + " at:");
        while (endpoints != null) {
            String[] endpointStr = new String[1];
            OCMain.endpointToString(endpoints, endpointStr);
            System.out.println(endpointStr[0]);
            endpoints = endpoints.getNext();
        }

        ObtMain.unownedDevices.add(uuid);
    }

}

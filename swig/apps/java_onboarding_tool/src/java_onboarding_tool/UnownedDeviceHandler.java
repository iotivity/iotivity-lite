package java_onboarding_tool;

import org.iotivity.OCEndpoint;
import org.iotivity.OCEndpointUtil;
import org.iotivity.OCMain;
import org.iotivity.OCObtDiscoveryHandler;
import org.iotivity.OCQos;
import org.iotivity.OCUuidUtil;
import org.iotivity.OCUuid;

public class UnownedDeviceHandler implements OCObtDiscoveryHandler {

    @Override
    public void handler(OCUuid uuid, OCEndpoint endpoints) {
        String deviceId = OCUuidUtil.uuidToString(uuid);
        System.out.println("\nDiscovered unowned device: "+ deviceId + " at:");
        OCEndpoint ep = endpoints;
        while (endpoints != null) {
            String[] endpointStr = new String[1];
            OCEndpointUtil.toString(endpoints, endpointStr);
            System.out.println(endpointStr[0]);
            endpoints = endpoints.getNext();
        }

        OCMain.doGet("/oic/d", ep, null, getUnownedDeviceNameHandler, OCQos.LOW_QOS);
    }

    public static GetUnownedDeviceNameHandler getUnownedDeviceNameHandler = new GetUnownedDeviceNameHandler();
}

package java_onboarding_tool;

import org.iotivity.OCEndpoint;
import org.iotivity.OCEndpointUtil;
import org.iotivity.OCMain;
import org.iotivity.OCObtDiscoveryHandler;
import org.iotivity.OCQos;
import org.iotivity.OCUuidUtil;
import org.iotivity.OCUuid;

public class OwnedDeviceHandler implements OCObtDiscoveryHandler {

    @Override
    public void handler(OCUuid uuid, OCEndpoint endpoints) {
        String deviceId = OCUuidUtil.uuidToString(uuid);
        System.out.println("\nDiscovered owned device: "+ deviceId + " at:");
        OCEndpoint ep = endpoints;
        while (endpoints != null) {
            String endpointStr = OCEndpointUtil.toString(endpoints);
            System.out.println(endpointStr);
            endpoints = endpoints.getNext();
        }

        OCMain.doGet("/oic/d", ep, null, getOwnedDeviceNameHandler, OCQos.HIGH_QOS);
    }

    public static GetOwnedDeviceNameHandler getOwnedDeviceNameHandler = new GetOwnedDeviceNameHandler();
}

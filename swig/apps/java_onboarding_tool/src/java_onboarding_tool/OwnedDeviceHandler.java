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
    public void handler(OCUuid uuid, OCEndpoint[] endpoints) {
        String deviceId = OCUuidUtil.uuidToString(uuid);
        System.out.println("\nDiscovered owned device: "+ deviceId + " at:");
        for (OCEndpoint endpoint : endpoints) {
            String endpointStr = OCEndpointUtil.toString(endpoint);
            System.out.println(endpointStr);
        }

        OCMain.doGet("/oic/d", endpoints[0], null, getOwnedDeviceNameHandler, OCQos.HIGH_QOS);
    }

    public static GetOwnedDeviceNameHandler getOwnedDeviceNameHandler = new GetOwnedDeviceNameHandler();
}

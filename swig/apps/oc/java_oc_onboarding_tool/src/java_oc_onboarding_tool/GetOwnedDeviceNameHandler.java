package java_oc_onboarding_tool;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetOwnedDeviceNameHandler implements OCResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("Get Owned Device Name Handler:");
        OcfDeviceInfo deviceInfo = OcfDeviceInfo.createFromRep(new OcRepresentation(response.getPayload()));
        if (deviceInfo != null) {
            ObtMain.ownedDevices.add(deviceInfo);
        }
    }
}

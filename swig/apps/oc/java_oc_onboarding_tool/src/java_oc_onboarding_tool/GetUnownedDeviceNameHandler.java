package java_oc_onboarding_tool;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetUnownedDeviceNameHandler implements OCResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("Get Unowned Device Name Handler:");
        OcfDeviceInfo deviceInfo = OcfDeviceInfo.createFromRep(new OcRepresentation(response.getPayload()));
        if (deviceInfo != null) {
            ObtMain.unownedDevices.add(deviceInfo);
        }
    }
}

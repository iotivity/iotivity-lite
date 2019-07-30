package java_oc_onboarding_tool;

import org.iotivity.*;
import org.iotivity.oc.*;

public class OtmCertificationHandler implements OCObtDeviceStatusHandler {

    // The UUID will be changed from the temporary UUID to the actual UUID once
    // OTM is completed. So we don't have to repeat the get on the device we
    // save the unowned device info so it's name can be moved to the owned
    // device.
    public OcfDeviceInfo unownedDeviceInfo;

    OtmCertificationHandler(OcfDeviceInfo deviceInfo) {
        unownedDeviceInfo = deviceInfo;
    }

    @Override
    public void handler(OCUuid uuid, int status) {
        if (status >= 0) {
            System.out.println("\nSuccessfully performed OTM on device " + OCUuidUtil.uuidToString(uuid));
            ObtMain.ownedDevices.add(new OcfDeviceInfo(uuid, unownedDeviceInfo.getName()));
        } else {
            System.out.println("\nERROR performing ownership transfer on device " + OCUuidUtil.uuidToString(uuid));
        }
    }
}

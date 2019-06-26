package java_onboarding_tool;

import org.iotivity.OCObtDeviceStatusHandler;
import org.iotivity.OCUuidUtil;
import org.iotivity.OCUuid;

public class JustWorksHandler implements OCObtDeviceStatusHandler {

    JustWorksHandler(OCFDeviceInfo deviceInfo) {
        oldDevInfo = deviceInfo;
    }

    @Override
    public void handler(OCUuid uuid, int status) {
        if (status >= 0) {
            System.out.println("\nSuccessfully performed OTM on device " + OCUuidUtil.uuidToString(uuid));
            ObtMain.ownedDevices.add(new OCFDeviceInfo(uuid, oldDevInfo.name));
        } else {
            System.out.println("\nERROR performing ownership transfer on device " + OCUuidUtil.uuidToString(uuid));
        }
    }

    // The UUID will be changed from the temporary UUID to the actual UUID once OTM is completed. So we don't
    // have to repeat the get on the device we place the old device info into the member variable so it can be
    // moved to the new device.
    public OCFDeviceInfo oldDevInfo;
}

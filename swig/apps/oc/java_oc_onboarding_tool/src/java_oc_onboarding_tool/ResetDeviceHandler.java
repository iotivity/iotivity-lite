package java_oc_onboarding_tool;

import org.iotivity.*;
import org.iotivity.oc.*;

public class ResetDeviceHandler implements OCObtDeviceStatusHandler {

    @Override
    public void handler(OCUuid uuid, int status) {
        if (status >= 0) {
            System.out.println("\nSuccessfully performed hard RESET to device " + OCUuidUtil.uuidToString(uuid));
            ObtMain.ownedDevices.remove(uuid);
        } else {
            System.out.println("\nERROR performing hard RESET to device " + OCUuidUtil.uuidToString(uuid));
        }
    }
}

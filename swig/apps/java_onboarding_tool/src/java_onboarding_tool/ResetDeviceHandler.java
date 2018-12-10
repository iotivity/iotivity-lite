package java_onboarding_tool;

import org.iotivity.OCObtDeviceStatusHandler;
import org.iotivity.OCUuid;
import org.iotivity.OCUuidType;

public class ResetDeviceHandler implements OCObtDeviceStatusHandler {

    @Override
    public void handler(OCUuidType uuid, int status, Object userData) {
        ObtMain.ownedDevices.remove(uuid);

        if (status >= 0) {
          System.out.println("\nSuccessfully performed hard RESET to device " + OCUuid.uuidToString(uuid));
        } else {
          System.out.println("\nERROR performing hard RESET to device " + OCUuid.uuidToString(uuid));
        }
    }

}

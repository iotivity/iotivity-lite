package java_onboarding_tool;

import org.iotivity.OCObtDeviceStatusHandler;
import org.iotivity.OCUuidUtil;
import org.iotivity.OCUuid;

public class GenerateRandomPinHandler implements OCObtDeviceStatusHandler {

    @Override
    public void handler(OCUuid uuid, int status) {
        if (status >= 0) {
            System.out.println("\nSuccessfully generated a Random PIN on device " + OCUuidUtil.uuidToString(uuid));
        } else {
            System.out.println("\nERROR generating a Random PIN on device " + OCUuidUtil.uuidToString(uuid));
        }
    }
}

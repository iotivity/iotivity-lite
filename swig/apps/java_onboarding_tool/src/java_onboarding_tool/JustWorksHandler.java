package java_onboarding_tool;

import org.iotivity.OCObtDeviceStatusHandler;
import org.iotivity.OCUuid;
import org.iotivity.OCUuidType;

public class JustWorksHandler implements OCObtDeviceStatusHandler {

    @Override
    public void handler(OCUuidType uuid, int status, Object userData) {
        if (status >= 0) {
          System.out.println("\nSuccessfully performed OTM on device " + OCUuid.uuidToString(uuid));
        } else {
          System.out.println("\nERROR performing ownership transfer on device " + OCUuid.uuidToString(uuid));
        }
    }

}

package java_oc_onboarding_tool;

import org.iotivity.*;
import org.iotivity.oc.*;

public class OtmRandomPinHandler implements OCObtDeviceStatusHandler {

    @Override
    public void handler(OCUuid uuid, int status) {
        if (status >= 0) {
            System.out.println("\nSuccessfully performed OTM on device " + OCUuidUtil.uuidToString(uuid));
        } else {
            System.out.println("\nERROR performing ownership transfer on device " + OCUuidUtil.uuidToString(uuid));
        }
    }
}

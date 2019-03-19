package java_oc_onboarding_tool;

import org.iotivity.*;
import org.iotivity.oc.*;

public class ProvisionAce2Handler implements OCObtDeviceStatusHandler {

    @Override
    public void handler(OCUuid uuid, int status) {
        if (status >= 0) {
            System.out.println("\nSuccessfully provisioned ACE to device " + OCUuidUtil.uuidToString(uuid));
        } else {
            ObtMain.ownedDevices.remove(uuid);
            System.out.println("\nERROR provisioning ACE to device " + OCUuidUtil.uuidToString(uuid));
        }
    }
}

package java_oc_onboarding_tool;

import org.iotivity.*;
import org.iotivity.oc.*;

public class ProvisionAuthWildcardAceHandler implements OCObtDeviceStatusHandler {

    @Override
    public void handler(OCUuid uuid, int status) {
        if (status >= 0) {
            System.out.println("\nSuccessfully provisioned auth-crypt * ACE to device " + OCUuidUtil.uuidToString(uuid));
        } else {
            for (OcfDeviceInfo od : ObtMain.ownedDevices) {
                if (od.getUuid().equals(uuid)) {
                    ObtMain.ownedDevices.remove(od);
                    break;
                }
            }
            System.out.println("\nERROR provisioning ACE to device " + OCUuidUtil.uuidToString(uuid));
        }
    }
}

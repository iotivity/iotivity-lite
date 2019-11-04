package java_onboarding_tool;

import org.iotivity.OCObtDeviceStatusHandler;
import org.iotivity.OCUuid;
import org.iotivity.OCUuidUtil;

public class ProvisionRoleWildcardAceHandler implements OCObtDeviceStatusHandler {

    @Override
    public void handler(OCUuid uuid, int status) {
        if (status >= 0) {
            System.out.println("\nSuccessfully provisioned role * ACE to device " + OCUuidUtil.uuidToString(uuid));
          } else {
            for (OCFDeviceInfo od : ObtMain.ownedDevices) {
                if (od.uuid.equals(uuid)) {
                    ObtMain.ownedDevices.remove(od);
                    break;
                }
            }
            System.out.println("\nERROR provisioning ACE to device " + OCUuidUtil.uuidToString(uuid));
          }
    }

}

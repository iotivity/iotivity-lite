package java_lite_simple_server;

import org.iotivity.OCMain;
import org.iotivity.OCOwnershipStatusHandler;
import org.iotivity.OCUuid;
import org.iotivity.OCUuidUtil;

public class OwnershipStatusHandler implements OCOwnershipStatusHandler {

    @Override
    public void handler(OCUuid uuid, long device_index, boolean owned) {
        System.out.print("Ownership Status: [" + device_index + "]" + OCUuidUtil.uuidToString(uuid));
        if (owned) {
            System.out.println(" owned.");
        } else {
            System.out.println(" un-owned.");
        }
    }
}

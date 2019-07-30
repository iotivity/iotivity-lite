package java_oc_onboarding_tool;

import org.iotivity.*;

public class GetOwnedDeviceNameHandler implements OCResponseHandler {

    @Override
    public void handler(OCClientResponse response) {
        System.out.println("Get Owned Device Name Handler:");
        OCRepresentation rep = response.getPayload();
        String n = null;
        String di = null;
        while (rep != null) {
            switch (rep.getType()) {
            case OC_REP_STRING:
                if ("n".equals(rep.getName())) {
                    n = rep.getValue().getString();
                }
                if ("di".equals(rep.getName())) {
                    di = rep.getValue().getString();
                }
                break;
            default:
                break;
            }
            rep = rep.getNext();
        }

        if (di != null) {
            ObtMain.ownedDevices.add(new OcfDeviceInfo(OCUuidUtil.stringToUuid(di), n));
        }
    }
}

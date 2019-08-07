package java_oc_onboarding_tool;

import org.iotivity.*;
import org.iotivity.oc.*;

public class OcfDeviceInfo {

    private static final String N_KEY = "n";
    private static final String DI_KEY = "di";

    private OCUuid uuid;
    private String name;

    OcfDeviceInfo(OCUuid uuid, String name) {
        this.uuid = uuid;
        this.name = name;
    }

    public OCUuid getUuid() {
        return uuid;
    }

    public String getName() {
        return name;
    }

    public int hashCode() {
        int result = 17;
        result = 37 * result + uuid.hashCode();
        result = 37 * result + name.hashCode();
        return result;
    }

    public boolean equals(Object obj) {
        OcfDeviceInfo other = (OcfDeviceInfo) obj;
        return (uuid.equals(other.uuid) && name.equals(other.name));
    }

    public static OcfDeviceInfo createFromRep(OcRepresentation rep) {
        OcfDeviceInfo ocfDeviceInfo = null;

        String n = null;
        String di = null;

        while (rep != null) {
            try {
                if (N_KEY.equals(rep.getKey())) {
                    n = rep.getString(N_KEY);
                }
                if (DI_KEY.equals(rep.getKey())) {
                    di = rep.getString(DI_KEY);
                }
            } catch (OcCborException e) {
                System.err.println(e.getMessage());
            }
            rep = rep.getNext();
        }

        if ((di != null) && (n != null)) {
            ocfDeviceInfo = new OcfDeviceInfo(OCUuidUtil.stringToUuid(di), n);
        }

        return ocfDeviceInfo;
    }
}

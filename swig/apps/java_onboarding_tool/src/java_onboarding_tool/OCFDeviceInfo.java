package java_onboarding_tool;

import org.iotivity.OCUuid;

public class OCFDeviceInfo {

    public OCUuid uuid;
    public String name;
    
    OCFDeviceInfo(OCUuid uuid, String name) {
        this.uuid = uuid;
        this.name = name;
    }
    
    public int hashCode() {
        int result = 17;
        result = 37 * result + uuid.hashCode();
        result = 37 * result + name.hashCode();
        return result;
    }
    
    public boolean equals(Object obj) {
        OCFDeviceInfo other = (OCFDeviceInfo) obj;
        return (uuid.equals(other.uuid) && name.equals(other.name));
    }
}

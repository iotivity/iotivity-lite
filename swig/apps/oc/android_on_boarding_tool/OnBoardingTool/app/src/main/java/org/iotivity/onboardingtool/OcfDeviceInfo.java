package org.iotivity.onboardingtool;

import org.iotivity.OCUuid;

public class OcfDeviceInfo {

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
}

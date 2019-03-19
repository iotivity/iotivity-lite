package org.iotivity.oc;

import org.iotivity.*;

public abstract class OcSecurityAce {

    protected OCSecurityAce nativeSecurityAce;

    // permission is one of OCAcePermissionsMask
    public void addPermission(int permission) {
        if (nativeSecurityAce != null) {
            OCObt.aceAddPermission(nativeSecurityAce, permission);
        }
    }

    OCSecurityAce getNativeSecurityAce() {
        return nativeSecurityAce;
    }
}

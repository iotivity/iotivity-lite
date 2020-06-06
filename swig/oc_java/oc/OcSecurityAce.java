package org.iotivity.oc;

import org.iotivity.*;

/**
 * OcSecurityAce is the base class of all Security Access Control Entries.
 * <p>
 * Only a derived SecurityAce class can be instantiated.
 */
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

package org.iotivity.oc;

import org.iotivity.*;

public class OcRoleSecurityAce extends OcSecurityAce {

    public OcRoleSecurityAce(String role, String authority) {
        nativeSecurityAce = OCObt.newAceForRole(role, authority);
    }
}

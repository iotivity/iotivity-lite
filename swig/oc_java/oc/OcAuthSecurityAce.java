package org.iotivity.oc;

import org.iotivity.*;

public class OcAuthSecurityAce extends OcSecurityAce {

    public OcAuthSecurityAce() {
        nativeSecurityAce = OCObt.newAceForConnection(OCAceConnectionType.OC_CONN_AUTH_CRYPT);
    }
}

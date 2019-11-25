package org.iotivity.oc;

import org.iotivity.*;

public class OcAnonSecurityAce extends OcSecurityAce {

    public OcAnonSecurityAce() {
        nativeSecurityAce = OCObt.newAceForConnection(OCAceConnectionType.OC_CONN_ANON_CLEAR);
    }
}

package org.iotivity.oc;

import org.iotivity.*;

public class OcSubjectSecurityAce extends OcSecurityAce {

    public OcSubjectSecurityAce(OCUuid uuid) {
        nativeSecurityAce = OCObt.newAceForSubject(uuid);
    }
}

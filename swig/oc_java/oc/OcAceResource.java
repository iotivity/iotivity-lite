package org.iotivity.oc;

import org.iotivity.*;

public class OcAceResource {

    private OCAceResource nativeResource;

    public OcAceResource(OcSecurityAce securityAce) {
        nativeResource = OCObt.aceNewResource(securityAce.getNativeSecurityAce());
        if (nativeResource == null) {
            OCObt.freeAce(securityAce.getNativeSecurityAce());
        }
    }

    public void setHref(String href) {
        if (nativeResource != null) {
            OCObt.aceResourceSetHref(nativeResource, href);
        }
    }

    public void setWildcard(OCAceWildcard wildcard) {
        if (nativeResource != null) {
            OCObt.aceResourceSetWc(nativeResource, wildcard);
        }
    }
}

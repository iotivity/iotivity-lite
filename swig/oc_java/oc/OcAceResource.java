package org.iotivity.oc;

import org.iotivity.*;

public class OcAceResource {

    private String uri;
    private String[] resourceTypes;
    private int[] interfaceMasks; // each entry is one of from OCInterfaceMask

    private boolean discoverable;
    private boolean observable;
    private int periodicObservable;

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

    public void setNumberOfResourceTypes(int numRts) {
        if (nativeResource != null) {
            OCObt.aceResourceSetNumRt(nativeResource, numRts);
        }
    }

    public void bindResourceType(String rt) {
        if (nativeResource != null) {
            OCObt.aceResourceBindRt(nativeResource, rt);
        }
    }

    public void bindResourceTypes(String[] rts) {
        if (nativeResource != null) {
            OCObt.aceResourceSetNumRt(nativeResource, rts.length);
            for (String rt : rts) {
                OCObt.aceResourceBindRt(nativeResource, rt);
            }
        }
    }

    // iface is one of OCAcePermissionsMask
    public void bindInterface(int iface) {
        if (nativeResource != null) {
            OCObt.aceResourceBindIf(nativeResource, iface);
        }
    }
}

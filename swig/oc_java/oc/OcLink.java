package org.iotivity.oc;

import org.iotivity.*;

public class OcLink {

    private OcResource resource; // href is uri of resource
    private OCLink nativeLink;

    public OcLink(OcResource resource) {
        this(resource, 0, null);
    }

    public OcLink(OcResource resource, long instance, String[] relations) {
        if (resource != null) {
            nativeLink = OCMain.newLink(resource.getNativeResource());
            if (nativeLink != null) {
                this.resource = resource;
                setInstance(instance);
                addRelations(relations);
            }
        } else {
            throw new IllegalArgumentException("OcResource cannot be null");
        }
    }

    public OcResource getResource() {
        return resource;
    }

    public long getInstance() {
        return nativeLink.getIns();
    }

    public void setInstance(long instance) {
        if (instance != 0) {
            nativeLink.setIns(instance);
        }
    }

    public String[] getRelations() {
        return nativeLink.getRel();
    }

    public void addRelations(String[] relations) {
        if (relations != null) {
            for (String relation : relations) {
                addRelation(relation);
            }
        }
    }

    public void addRelation(String relation) {
        if (relation != null) {
            OCMain.linkAddRelation(nativeLink, relation);
        }
    }

    OCLink getNativeLink() {
        return nativeLink;
    }
}

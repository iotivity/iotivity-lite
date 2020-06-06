package org.iotivity.oc;

import org.iotivity.*;

/**
 * OcLink is a resource link.
 * <p>
 * Links are typically added to a collection in the registerResources() method of the platform's initialize handler.
 *
 * @see OcPlatform#systemInit
 * @see OcCollection#addLink
 * @see OCMainInitHandler#registerResources
 */
public class OcLink {

    private OcResource resource; // href is uri of resource
    private OCLink nativeLink;

    /**
     * Constructs an OcLink.
     * <p>
     * @param resource  the resource this link represents
     */
    public OcLink(OcResource resource) {
        this(resource, 0, null);
    }

    /**
     * Constructs an OcLink.
     * <p>
     * @param resource  the resource this link represents
     * @param instance  the instance of this link
     * @param relations  array of the relationships
     */
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

package org.iotivity.oc;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.iotivity.*;

/**
 * OcCollection is a collection of a device.
 * <p>
 * Collections are typically added to a device in the registerResources() method of the platform's initialize handler.
 *
 * @see OcPlatform#systemInit
 * @see OcDevice#addCollection
 * @see OCMainInitHandler#registerResources
 * @see OcLink
 */
public class OcCollection extends OcResource {

    private Map<OcLink, OCLink> linkLookup = new ConcurrentHashMap<>();

    private String[] supportedRts;
    private String[] mandatoryRts;

    /**
     * Constructs an OcCollection.
     * <p>
     * @param device  the device owning this collection
     * @param name  the name of this collection
     * @param uri  the uri of this collection
     * @param rts  array of the resource types
     * @param sRts  array of the supported resource types
     * @param mRts  array of the mandatory resource types
     */
    public OcCollection(OcDevice device, String name, String uri, String[] rts, String[] sRts, String[] mRts) {
        super();
        if (device == null) {
            throw new IllegalArgumentException("OcDevice cannot be null");
        }

        this.name = (name != null) ? name : "";
        this.uri = (uri != null) ? uri : "";
        this.resourceTypes = (rts != null) ? rts : new String[0];
        this.interfaceMasks = new int[0];

        supportedRts = (sRts != null) ? sRts : new String[0];
        mandatoryRts = (mRts != null) ? mRts : new String[0];

        nativeResource = OCMain.newCollection(this.name, this.uri, (short) this.resourceTypes.length,
                device.getDeviceIndex());

        if (nativeResource != null) {
            for (String resourceType : this.resourceTypes) {
                OCMain.resourceBindResourceType(nativeResource, resourceType);
            }
            for (String resourceType : supportedRts) {
                OCMain.collectionAddSupportedResourceType(nativeResource, resourceType);
            }
            for (String resourceType : mandatoryRts) {
                OCMain.collectionAddMandatoryResourceType(nativeResource, resourceType);
            }
        }
    }

    public String[] getSupportedRts() {
        return supportedRts;
    }

    public String[] getMandatoryRts() {
        return mandatoryRts;
    }

    public void addLink(OcLink link) {
        if (link != null) {
            OCMain.collectionAddLink(nativeResource, link.getNativeLink());

            // save the OCLink for future lookup
            linkLookup.put(link, link.getNativeLink());
        }
    }

    public void deleteLink(OcLink link) {
        if (link != null) {
            linkLookup.remove(link);
            OCMain.deleteLink(link.getNativeLink());
        }
    }

    public OcLink[] getLinks() {
        return linkLookup.keySet().toArray(new OcLink[0]);
    }
}

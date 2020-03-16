package org.iotivity.oc;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.iotivity.*;

public class OcCollection extends OcResource {

    private Map<OcLink, OCLink> linkLookup = new ConcurrentHashMap<>();

    private String[] supportedRts;
    private String[] mandatoryRts;

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

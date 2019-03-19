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
                (short) supportedRts.length, (short) mandatoryRts.length, device.getDeviceIndex());

        if (nativeResource != null) {
            for (String resourceType : this.resourceTypes) {
                OCMain.resourceBindResourceType(nativeResource, resourceType);
            }
            for (String resourceType : supportedRts) {
                OCMain.collectionAddSupportedRt(nativeResource, resourceType);
            }
            for (String resourceType : mandatoryRts) {
                OCMain.collectionAddMandatoryRt(nativeResource, resourceType);
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
            if (nativeResource == null) {
                throw new NullPointerException(
                        "Collection must be added to the device before links can be added to the collection");
            }
            OCLink OC_link = OCMain.newLink(link.getResource().getNativeResource());
            for (String relation : link.getRelations()) {
                OCMain.linkAddRelation(OC_link, relation);
            }
            if (link.getInstance() != null) {
                OCMain.linkSetInstance(OC_link, link.getInstance());
            }

            OCMain.collectionAddLink(nativeResource, OC_link);

            // save the OCLink for future lookup
            linkLookup.put(link, OC_link);
        }
    }

    public void deleteLink(OcLink link) {
        if (link != null) {
            OCLink OC_link = linkLookup.remove(link);
            if (OC_link != null) {
                OCMain.deleteLink(OC_link);
            }
        }
    }

    public OcLink[] getLinks() {
        return linkLookup.keySet().toArray(new OcLink[0]);
    }
}

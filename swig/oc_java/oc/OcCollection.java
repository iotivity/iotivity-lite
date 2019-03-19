package org.iotivity.oc;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.iotivity.*;

public class OcCollection extends OcResource {

    private Map<OcLink, OCLink> linkLookup = new ConcurrentHashMap<>();

    private String[] supportedRts;
    private String[] mandatoryRts;

    public OcCollection(String name, String uri, String[] rts, int[] ifMasks, String[] sRts, String[] mRts) {
        super(name, uri, rts, ifMasks);
        supportedRts = (sRts != null) ? sRts : new String[0];
        mandatoryRts = (mRts != null) ? mRts : new String[0];
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
            OCLink OC_link = OCMain.newLink(nativeResource);
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

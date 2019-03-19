package org.iotivity.oc;

import java.util.ArrayList;
import java.util.List;

import org.iotivity.*;

public class OcLink {

    private OcResource resource; // href is uri of resource
    private String instance;
    private List<String> relations = new ArrayList<>();

    protected OCLink nativeLink;

    public OcLink(OcResource resource) {
        this(resource, null, null);
    }

    public OcLink(OcResource resource, String instance, List<String> relations) {
        if (resource != null) {
            this.resource = resource;
            setInstance(instance);
            addRelations(relations);

            nativeLink = OCMain.newLink(resource.getNativeResource());
            for (String relation : this.relations) {
                OCMain.linkAddRelation(nativeLink, relation);
            }
            if (this.instance != null) {
                OCMain.linkSetInstance(nativeLink, this.instance);
            }

        } else {
            throw new IllegalArgumentException("OcResource cannot be null");
        }
    }

    public OcResource getResource() {
        return resource;
    }

    public String getInstance() {
        return instance;
    }

    public void setInstance(String instance) {
        this.instance = instance;
    }

    public List<String> getRelations() {
        return relations;
    }

    public void addRelations(List<String> relations) {
        if (relations != null) {
            this.relations.addAll(relations);
        }
    }

    public void addRelation(String relation) {
        if (relation != null) {
            relations.add(relation);
        }
    }

    OCLink getNativeLink() {
        return nativeLink;
    }
}

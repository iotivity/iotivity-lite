package org.iotivity.oc;

import java.util.ArrayList;
import java.util.List;

import org.iotivity.*;

public class OcLink {

    private OcResource resource; // href is uri of resource
    private String instance;
    private List<String> relations = new ArrayList<>();

    public OcLink(OcResource resource) {
        this(resource, null, null);
    }

    public OcLink(OcResource resource, String instance, List<String> relations) {
        if (resource != null) {
            this.resource = resource;
            if (instance != null) {
                setInstance(instance);
            }
            if (relations != null) {
                addRelations(relations);
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
            this.relations.add(relation);
        }
    }
}

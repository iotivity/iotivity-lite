package org.iotivity.multideviceserver;

import java.util.ArrayList;
import java.util.List;

public class Television {

    static public final String MEDIA_LIST_KEY = "medialist";

    private String name;
    private List<Media> mediaList = new ArrayList<>();

    public Television(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public Media[] getMediaList() {
        return mediaList.toArray(new Media[0]);
    }

    public void addMedia(Media media) {
        if (media != null) {
            mediaList.add(media);
        }
    }
}

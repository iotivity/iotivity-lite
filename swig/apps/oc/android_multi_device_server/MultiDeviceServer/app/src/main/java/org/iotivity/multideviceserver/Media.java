package org.iotivity.multideviceserver;

import org.iotivity.oc.OcCborException;
import org.iotivity.oc.OcRepresentation;

import java.util.ArrayList;
import java.util.List;

public class Media {

    static public final String URL_KEY = "url";
    static public final String SDP_KEY = "sdp";

    private String name;
    private String url;
    private List<String> sdpLines = new ArrayList<>();

    public Media(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String[] getSdp() {
        return sdpLines.toArray(new String[0]);
    }

    public void addSdp(String sdp) {
        if (sdp != null) {
            sdpLines.add(sdp);
        }
    }

    static public Media createFromOcRepresentation(OcRepresentation mediaObject) {
        Media media = new Media("");
        while (mediaObject != null) {
            try {
                if (Media.URL_KEY.equalsIgnoreCase(mediaObject.getKey())) {
                    media.setUrl(mediaObject.getString(Media.URL_KEY));
                }
            } catch (OcCborException e) {
                // ignore -- no url
            }

            try {
                if (Media.SDP_KEY.equalsIgnoreCase(mediaObject.getKey())) {
                    String[] sdpLines = mediaObject.getStringArray(Media.SDP_KEY);
                    for (String sdp : sdpLines) {
                        media.addSdp(sdp);
                    }
                }
            } catch (OcCborException e) {
                // ignore -- no sdp
            }

            mediaObject = mediaObject.getNext();
        }

        return media;
    }
}

package java_oc_simple_media_server;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MediaResource {

    private String name;
    private String url;
    private List<String> sdp = new ArrayList<>();

    public MediaResource(String name) {
        setName(name);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = (name != null) ? name : "";
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = (url != null) ? url : "";
    }

    public String[] getSdpLines() {
        return sdp.toArray(new String[0]);
    }

    public void setSdp(String[] sdp) {
        if (sdp != null) {
            this.sdp.clear();
            Collections.addAll(this.sdp, sdp);
        }
    }
}

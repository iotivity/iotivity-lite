package java_oc_channel_change_server;

public class MediaInput {

    private MediaSource[] mediaSources;

    public MediaInput() {
        this(null);
    }

    public MediaInput(MediaSource[] mediaSources) {
        setMediaSources(mediaSources);
    }

    public MediaSource[] getMediaSources() {
        return mediaSources;
    }

    public void setMediaSources(MediaSource[] mediaSources) {
        this.mediaSources = ((mediaSources != null) ? mediaSources : new MediaSource[0]);
    }
}

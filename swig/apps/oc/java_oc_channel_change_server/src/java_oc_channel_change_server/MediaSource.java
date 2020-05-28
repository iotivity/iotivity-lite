package java_oc_channel_change_server;

public class MediaSource {

    public enum SourceType {
        audioOnly, videoOnly, audioPlusVideo
    }

    private String sourceName;
    private String sourceNumber;
    private SourceType sourceType;
    private boolean status;

    public MediaSource() {
        this("", false);
    }

    public MediaSource(String sourceName, boolean status) {
        this(sourceName, status, SourceType.audioPlusVideo, "0");
    }

    public MediaSource(String sourceName, boolean status, SourceType sourceType, String sourceNumber) {
        setSourceName(sourceName);
        setSourceNumber(sourceNumber);
        setSourceType(sourceType);
        setSourceStatus(status);
    }

    public String getSourceName() {
        return sourceName;
    }

    public void setSourceName(String sourceName) {
        this.sourceName = sourceName;
    }

    public String getSourceNumber() {
        return sourceNumber;
    }

    public void setSourceNumber(String sourceNumber) {
        this.sourceNumber = sourceNumber;
    }

    public SourceType getSourceType() {
        return sourceType;
    }

    public void setSourceType(SourceType sourceType) {
        this.sourceType = sourceType;
    }

    public boolean getSourceStatus() {
        return status;
    }

    public void setSourceStatus(boolean status) {
        this.status = status;
    }
}

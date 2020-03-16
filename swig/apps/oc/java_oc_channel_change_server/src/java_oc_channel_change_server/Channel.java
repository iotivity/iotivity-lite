package java_oc_channel_change_server;

public class Channel {

    static public final String ACTION_KEY = "action";
    static public final String CHANNELID_KEY = "channelid";

    static public final String CHANNELUP_ACTION = "channelup";
    static public final String CHANNELDOWN_ACTION = "channeldown";

    static public final int MAX_CHANNEL = 9999;

    static private final String[] channelStatus = new String[] { "OK", "Parental", "PPV", "Unsubscribed" };

    private int channel;
    private String name;
    private String status;
    private Object[] epg; // TODO:

    public Channel(int channel) {
        this(channel, "Channel " + channel);
    }

    public Channel(int channel, String name) {
        setChannel(channel);
        setName(name);
        setStatus(channelStatus[0]);
    }

    public int getChannel() {
        return channel;
    }

    private void setChannel(int channel) {
        this.channel = (channel > 0) ? channel : 0;
    }

    public String getName() {
        return name;
    }

    private void setName(String name) {
        this.name = (name != null) ? name : "";
    }

    public String getStatus() {
        return status;
    }

    private void setStatus(String status) {
        this.status = (status != null) ? status : "";
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{ ");
        sb.append("{\"currentchannel\", " + getChannel() + "}, ");
        sb.append("{\"channelname\", " + getName() + "}, ");
        sb.append("{\"channelstatus\", " + getStatus() + "}, ");
        sb.append("{\"channelepg\", " + "[]" + "}"); // TODO: epg[]
        sb.append(" }");
        return sb.toString();
    }
}

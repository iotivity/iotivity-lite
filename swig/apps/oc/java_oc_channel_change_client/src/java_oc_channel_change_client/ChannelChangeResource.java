package java_oc_channel_change_client;

import java.util.Arrays;

public class ChannelChangeResource extends OcfServerResource {

    private int currentChannel;
    private String channelName;
    private String channelStatus;
    private String[] actions;
    private Object[] channelEpg; // TODO:

    public ChannelChangeResource() {
    }

    public int getCurrentChannel() {
        return currentChannel;
    }

    public void setCurrentChannel(int channel) {
        currentChannel = channel;
    }

    public String getChannelName() {
        return channelName;
    }

    public void setChannelName(String name) {
        channelName = name;
    }

    public String getChannelStatus() {
        return channelStatus;
    }

    public void setChannelStatus(String status) {
        channelStatus = status;
    }

    public String[] getActions() {
        return (actions != null) ? actions : new String[0];
    }

    public void setActions(String[] actions) {
        this.actions = actions;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{ ");
        sb.append("{\"currentchannel\", " + getCurrentChannel() + "}, ");
        sb.append("{\"channelname\", " + getChannelName() + "}, ");
        sb.append("{\"channelstatus\", " + getChannelStatus() + "}, ");
        sb.append("{\"actions\", " + Arrays.toString(getActions()) + "}, ");
        sb.append("{\"channelepg\", " + "[]" + "}"); // TODO: epg[]
        sb.append(" }");
        return sb.toString();
    }
}

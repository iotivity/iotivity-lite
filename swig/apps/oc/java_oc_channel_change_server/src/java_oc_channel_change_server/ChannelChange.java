package java_oc_channel_change_server;

import java.util.HashMap;
import java.util.Map;

public class ChannelChange {

    static final private Map<Integer, Channel> channels = new HashMap<>();

    private String name;
    private Channel currentChannel;

    public ChannelChange(String name) {
        setName(name);
        setCurrentChannel(1);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = (name != null) ? name : "";
    }

    public Channel getCurrentChannel() {
        return currentChannel;
    }

    synchronized public void setCurrentChannel(int channelId) {
        if (!channels.containsKey(channelId)) {
            channels.put(channelId, new Channel(channelId));
        }
        currentChannel = channels.get(channelId);
        System.out.println("Set Channel Id: " + currentChannel.toString());
    }

    synchronized public void channelUp() {
        System.out.print("Channel Up: ");
        setCurrentChannel((currentChannel.getChannel() == Channel.MAX_CHANNEL) ? 1 : (currentChannel.getChannel() + 1));
    }

    synchronized public void channelDown() {
        System.out.print("Channel Down: ");
        setCurrentChannel((currentChannel.getChannel() == 1) ? Channel.MAX_CHANNEL : (currentChannel.getChannel() - 1));
    }
}

package java_oc_channel_change_server;

import org.iotivity.*;

public class PutChannelChange implements OCRequestHandler {

    private ChannelChange channelChange;

    public PutChannelChange(ChannelChange channelChange) {
        this.channelChange = channelChange;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        // System.out.println("Inside the PutChannelChange RequestHandler");
        new PostChannelChange(channelChange).handler(request, interfaces);
    }
}

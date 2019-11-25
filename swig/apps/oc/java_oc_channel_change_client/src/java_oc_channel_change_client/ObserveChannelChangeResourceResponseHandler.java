package java_oc_channel_change_client;

import org.iotivity.*;

public class ObserveChannelChangeResourceResponseHandler implements OCResponseHandler {

    private ChannelChangeResource channelChangeResource;

    public ObserveChannelChangeResourceResponseHandler(ChannelChangeResource channelChangeResource) {
        this.channelChangeResource = channelChangeResource;
    }

    @Override
    public void handler(OCClientResponse response) {
        new GetChannelChangeResourceResponseHandler(channelChangeResource).handler(response);
        System.out.println(channelChangeResource.toString());
    }
}

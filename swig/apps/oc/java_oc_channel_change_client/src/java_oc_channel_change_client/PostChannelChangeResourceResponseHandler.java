package java_oc_channel_change_client;

import org.iotivity.*;
import org.iotivity.oc.*;

public class PostChannelChangeResourceResponseHandler implements OCResponseHandler {

    private ChannelChangeResource channelChangeResource;

    public PostChannelChangeResourceResponseHandler(ChannelChangeResource channelChangeResource) {
        this.channelChangeResource = channelChangeResource;
    }

    @Override
    public void handler(OCClientResponse response) {
        if ((response.getCode() == OCStatus.OC_STATUS_CHANGED) || (response.getCode() == OCStatus.OC_STATUS_CREATED)) {
            new GetChannelChangeResourceResponseHandler(channelChangeResource).handler(response);
            return;
        }
        // unexpected response
        System.out.println("\nPOST response code " + response.getCode().toString() + " (" + response.getCode() + ")");
    }
}

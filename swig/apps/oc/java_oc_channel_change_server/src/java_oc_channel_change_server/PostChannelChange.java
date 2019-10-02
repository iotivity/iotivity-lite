package java_oc_channel_change_server;

import java.util.List;

import org.iotivity.*;
import org.iotivity.oc.*;

public class PostChannelChange implements OCRequestHandler {

    private ChannelChange channelChange;

    public PostChannelChange(ChannelChange channelChange) {
        this.channelChange = channelChange;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        // System.out.println("Inside the PostChannelChange RequestHandler");
        List<OCQueryValue> queryParams = OcUtils.getQueryValues(request);
        if (queryParams != null) {
            // Use query params
            for (OCQueryValue param : queryParams) {
                if (Channel.ACTION_KEY.equalsIgnoreCase(param.getKey())) {
                    String action = param.getValue();
                    System.out.println("action: " + action);
                    if (action.equalsIgnoreCase(Channel.CHANNELUP_ACTION)) {
                        channelChange.channelUp();
                    } else if (action.equalsIgnoreCase(Channel.CHANNELDOWN_ACTION)) {
                        channelChange.channelDown();
                    } else {
                        System.err.println("Unknown action: " + action);
                    }
                }
                if (Channel.CHANNELID_KEY.equalsIgnoreCase(param.getKey())) {
                    try {
                        int channelId = Integer.parseInt(param.getValue());
                        System.out.println("channel id: " + channelId);
                        channelChange.setCurrentChannel(channelId);
                    } catch (NumberFormatException e) {
                        System.err.println("Error channel id: " + param.getValue());

                    }
                }
            }

        } else {
            // Use represenation
            OcRepresentation rep = new OcRepresentation(request.getRequestPayload());
            while (rep != null) {
                try {
                    if (Channel.ACTION_KEY.equalsIgnoreCase(rep.getKey())) {
                        String action = rep.getString(Channel.ACTION_KEY);
                        System.out.println("action: " + action);
                        if (action.equalsIgnoreCase(Channel.CHANNELUP_ACTION)) {
                            channelChange.channelUp();
                        } else if (action.equalsIgnoreCase(Channel.CHANNELDOWN_ACTION)) {
                            channelChange.channelDown();
                        } else {
                            System.err.println("Unknown action: " + action);
                        }
                    }
                } catch (OcCborException e) {
                    // ignore -- no action
                }

                try {
                    if (Channel.CHANNELID_KEY.equalsIgnoreCase(rep.getKey())) {
                        int channelId = (int) rep.getLong(Channel.CHANNELID_KEY);
                        System.out.println("channel id: " + channelId);
                        channelChange.setCurrentChannel(channelId);
                    }
                } catch (OcCborException e) {
                    // ignore -- no channelid
                }

                rep = rep.getNext();
            }
        }

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        GetChannelChange.encodeReturnValue(root, channelChange);
        root.done();

        OcUtils.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

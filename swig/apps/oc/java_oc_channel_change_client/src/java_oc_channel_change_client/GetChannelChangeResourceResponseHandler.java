package java_oc_channel_change_client;

import java.util.ArrayList;
import java.util.List;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetChannelChangeResourceResponseHandler implements OCResponseHandler {

    private static final String CURRENTCHANNEL_KEY = "currentchannel";
    private static final String CHANNELNAME_KEY = "channelname";
    private static final String CHANNELSTATUS_KEY = "channelstatus";
    private static final String CHANNELEPG_KEY = "channelepg";
    private static final String ACTIONS_KEY = "actions";
    private static final String ACTION_KEY = "action";
    private static final String CHANNELUP_ACTION = "channelup";
    private static final String CHANNELDOWN_ACTION = "channeldown";

    private ChannelChangeResource channelChangeResource;

    public GetChannelChangeResourceResponseHandler(ChannelChangeResource channelChangeResource) {
        this.channelChangeResource = channelChangeResource;
    }

    @Override
    public void handler(OCClientResponse response) {

        if (response.getPayload() != null) {
            OcRepresentation rep = new OcRepresentation(response.getPayload());
            while (rep != null) {
                try {
                    if (CURRENTCHANNEL_KEY.equalsIgnoreCase(rep.getKey())) {
                        channelChangeResource.setCurrentChannel((int) rep.getLong(CURRENTCHANNEL_KEY));
                    }
                    if (CHANNELNAME_KEY.equalsIgnoreCase(rep.getKey())) {
                        channelChangeResource.setChannelName(rep.getString(CHANNELNAME_KEY));
                    }
                    if (CHANNELSTATUS_KEY.equalsIgnoreCase(rep.getKey())) {
                        channelChangeResource.setChannelStatus(rep.getString(CHANNELSTATUS_KEY));
                    }
                    if (CHANNELEPG_KEY.equalsIgnoreCase(rep.getKey())) {
                        // TODO:
                    }
                    if (ACTIONS_KEY.equalsIgnoreCase(rep.getKey())) {
                        List<String> actionsList = new ArrayList<>();
                        OcRepresentation actionsArray = rep.getObjectArray(ACTIONS_KEY);
                        while (actionsArray != null) {
                            OcRepresentation actionObject = actionsArray.getObject();
                            if (ACTION_KEY.equalsIgnoreCase(actionObject.getKey())) {
                                String action = actionObject.getString(ACTION_KEY);
                                actionsList.add(action);
                            }
                            actionsArray = actionsArray.getNext();
                        }
                        channelChangeResource.setActions(actionsList.toArray(new String[0]));
                    }
                } catch (OcCborException e) {
                    System.err.println(e.getMessage());
                }

                rep = rep.getNext();
            }
        }
    }
}

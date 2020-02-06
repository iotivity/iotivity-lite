package java_oc_channel_change_server;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetChannelChange implements OCRequestHandler {

    private ChannelChange channelChange;

    public GetChannelChange(ChannelChange channelChange) {
        this.channelChange = channelChange;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        // System.out.println("Inside the GetChannelChange RequestHandler");

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        switch (interfaces) {
        case OCInterfaceMask.BASELINE:
            root.processBaselineInterface(request.getResource());
            /* fall through */
        case OCInterfaceMask.RW:
            encodeReturnValue(root, channelChange);
            break;
        default:
            break;
        }
        root.done();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_OK);
    }

    static OcCborEncoder encodeReturnValue(OcCborEncoder root, ChannelChange channelChange) {
        root.setUnsignedInt("currentchannel", channelChange.getCurrentChannel().getChannel());
        root.setTextString("channelname", channelChange.getCurrentChannel().getName());
        root.setTextString("channelstatus", channelChange.getCurrentChannel().getStatus());
        OcCborEncoder actionsArray = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ARRAY, root,
                "actions");

        OcCborEncoder actionsArrayObject = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ARRAY_ITEM,
                actionsArray);
        actionsArrayObject.setTextString(Channel.ACTION_KEY, Channel.CHANNELUP_ACTION);
        actionsArrayObject.done();

        actionsArrayObject = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ARRAY_ITEM, actionsArray);
        actionsArrayObject.setTextString(Channel.ACTION_KEY, Channel.CHANNELDOWN_ACTION);
        actionsArrayObject.done();

        actionsArray.done();

        return root;
    }
}

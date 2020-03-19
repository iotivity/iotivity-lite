package java_oc_channel_change_server;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetMediaInput implements OCRequestHandler {

    private MediaInput mediaInput;

    public GetMediaInput(MediaInput mediaInput) {
        this.mediaInput = mediaInput;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the GetMediaInput RequestHandler");

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        switch (interfaces) {
        case OCInterfaceMask.BASELINE:
            root.processBaselineInterface(request.getResource());
            /* fall through */
        case OCInterfaceMask.A:
            encodeReturnValue(root, mediaInput);
            break;
        default:
            break;
        }
        root.done();

        OcUtils.sendResponse(request, OCStatus.OC_STATUS_OK);
    }

    static OcCborEncoder encodeReturnValue(OcCborEncoder root, MediaInput mediaInput) {
        OcCborEncoder mediaSourceList = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ARRAY, root,
                "sources");
        for (MediaSource mediaSource : mediaInput.getMediaSources()) {
            OcCborEncoder mediaSourceArrayItem = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ARRAY_ITEM,
                    mediaSourceList);
            mediaSourceArrayItem.setTextString("sourceName", mediaSource.getSourceName());
            mediaSourceArrayItem.setTextString("sourceNumber", mediaSource.getSourceNumber());
            mediaSourceArrayItem.setTextString("sourceType", mediaSource.getSourceType().toString());
            mediaSourceArrayItem.setBoolean("status", mediaSource.getSourceStatus());
            mediaSourceArrayItem.done();
        }
        mediaSourceList.done();

        return root;
    }
}

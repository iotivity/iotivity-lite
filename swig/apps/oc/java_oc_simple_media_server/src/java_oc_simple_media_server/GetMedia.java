package java_oc_simple_media_server;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetMedia implements OCRequestHandler {

    private MediaResource mediaResource;

    public GetMedia(MediaResource mediaResource) {
        this.mediaResource = mediaResource;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        // System.out.println("Inside the GetMedia RequestHandler");

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        switch (interfaces) {
        case OCInterfaceMask.BASELINE:
            root.processBaselineInterface(request.getResource());
            /* fall through */
        case OCInterfaceMask.RW:
            root.setTextString("name", mediaResource.getName());
            root.setTextString("url", mediaResource.getUrl());
            break;
        default:
            break;
        }
        root.done();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_OK);
    }
}

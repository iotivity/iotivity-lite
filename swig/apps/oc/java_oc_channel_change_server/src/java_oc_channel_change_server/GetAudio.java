package java_oc_channel_change_server;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetAudio implements OCRequestHandler {

    private Audio audioControl;

    public GetAudio(Audio audioControl) {
        this.audioControl = audioControl;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the GetAudio RequestHandler");

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        switch (interfaces) {
        case OCInterfaceMask.BASELINE:
            root.processBaselineInterface(request.getResource());
            /* fall through */
        case OCInterfaceMask.RW:
            encodeReturnValue(root, audioControl);
            break;
        default:
            break;
        }
        root.done();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_OK);
    }

    static OcCborEncoder encodeReturnValue(OcCborEncoder root, Audio audioControl) {
        root.setBoolean("mute", audioControl.isMute());
        root.setLong("volume", audioControl.getVolume());
        return root;
    }
}

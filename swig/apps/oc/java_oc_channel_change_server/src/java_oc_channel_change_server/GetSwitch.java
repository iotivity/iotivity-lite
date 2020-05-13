package java_oc_channel_change_server;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetSwitch implements OCRequestHandler {

    private Switch binarySwitch;

    public GetSwitch(Switch binarySwitch) {
        this.binarySwitch = binarySwitch;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the GetSwitch RequestHandler");

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        switch (interfaces) {
        case OCInterfaceMask.BASELINE:
            root.processBaselineInterface(request.getResource());
            /* fall through */
        case OCInterfaceMask.RW:
            encodeReturnValue(root, binarySwitch);
            break;
        default:
            break;
        }
        root.done();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_OK);
    }

    static OcCborEncoder encodeReturnValue(OcCborEncoder root, Switch binarySwitch) {
        root.setBoolean("value", binarySwitch.getValue());
        return root;
    }
}

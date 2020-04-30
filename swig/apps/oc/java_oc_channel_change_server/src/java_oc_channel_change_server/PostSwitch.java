package java_oc_channel_change_server;

import org.iotivity.*;
import org.iotivity.oc.*;

public class PostSwitch implements OCRequestHandler {

    private Switch binarySwitch;

    public PostSwitch(Switch binarySwitch) {
        this.binarySwitch = binarySwitch;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        System.out.println("Inside the PostSwitch RequestHandler");
        OcRepresentation rep = new OcRepresentation(request.getRequestPayload());
        while (rep != null) {
            try {
                if ("value".equalsIgnoreCase(rep.getKey())) {
                    boolean value = rep.getBoolean("value");
                    System.out.println("value: " + value);
                    binarySwitch.setValue(value);
                }
            } catch (OcCborException e) {
                // ignore -- no value
            }

            rep = rep.getNext();
        }

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        GetSwitch.encodeReturnValue(root, binarySwitch);
        root.done();

        OcUtils.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

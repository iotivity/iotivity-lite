package java_oc_simple_media_server;

import org.iotivity.*;
import org.iotivity.oc.*;

public class GetMediaControl implements OCRequestHandler {

    private MediaController controller;

    public GetMediaControl(MediaController controller) {
        this.controller = controller;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        // System.out.println("Inside the GetMediaControl RequestHandler");

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        switch (interfaces) {
        case OCInterfaceMask.BASELINE:
            root.processBaselineInterface(request.getResource());
            /* fall through */
        case OCInterfaceMask.RW:
            encodeReturnValue(root, controller);
            break;
        default:
            break;
        }
        root.done();
        OcUtils.sendResponse(request, OCStatus.OC_STATUS_OK);
    }

    static OcCborEncoder encodeReturnValue(OcCborEncoder root, MediaController controller) {
        root.setTextString("name", controller.getName());
        root.setBoolean("playstate", controller.getPlayState());
        root.setTextString("mediaaction", controller.getCurrentAction());
        OcCborEncoder mediaActionsArray = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ARRAY, root,
                "mediaactions");
        for (String mediaAction : controller.getAllowedActions()) {
            OcCborEncoder mediaActionArrayObject = OcCborEncoder
                    .createOcCborEncoder(OcCborEncoder.EncoderType.ARRAY_ITEM, mediaActionsArray);
            mediaActionArrayObject.setTextString("mediaaction", mediaAction);
            if ("fastforward".equalsIgnoreCase(mediaAction)) {
                double[] allowedValues = controller.getFastforwardAllowedValues();
                if (allowedValues != null) {
                    mediaActionArrayObject.setDoubleArray("allowedvalues", allowedValues);
                }
            }
            if ("rewind".equalsIgnoreCase(mediaAction)) {
                double[] allowedValues = controller.getRewindAllowedValues();
                if (allowedValues != null) {
                    mediaActionArrayObject.setDoubleArray("allowedvalues", allowedValues);
                }
            }
            if ("stepforward".equalsIgnoreCase(mediaAction)) {
                double[] range = controller.getStepForwardRange();
                if (range != null) {
                    mediaActionArrayObject.setDoubleArray("range", range);
                }
                Double step = controller.getStep();
                if (step != null) {
                    mediaActionArrayObject.setDouble("step", step);
                }
            }
            if ("stepbackward".equalsIgnoreCase(mediaAction)) {
                double[] range = controller.getStepBackwardRange();
                if (range != null) {
                    mediaActionArrayObject.setDoubleArray("range", range);
                }
                Double step = controller.getStep();
                if (step != null) {
                    mediaActionArrayObject.setDouble("step", step);
                }
            }
            if ("seek".equalsIgnoreCase(mediaAction)) {
                double[] range = controller.getSeekRange();
                if (range != null) {
                    mediaActionArrayObject.setDoubleArray("range", range);
                }
            }
            mediaActionArrayObject.done();
        }
        mediaActionsArray.done();
        root.setDouble("mediaspeed", controller.getSpeed());
        root.setDouble("medialocation", controller.getLocation());

        return root;
    }
}

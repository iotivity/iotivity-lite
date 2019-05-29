package java_oc_simple_media_server;

import org.iotivity.*;
import org.iotivity.oc.*;

public class PostMediaControl implements OCRequestHandler {

    private MediaController controller;

    public PostMediaControl(MediaController controller) {
        this.controller = controller;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        // System.out.println("Inside the PostMediaControl RequestHandler");
        OCRepresentation rep = request.getRequestPayload();
        while (rep != null) {
            if ("uriexp".equalsIgnoreCase(rep.getName()) && (OCType.OC_REP_STRING == rep.getType())) {
                String uriexp = rep.getValue().getString();
                System.out.println("uriexp: " + uriexp);
                String[] propertyAndValue = uriexp.split("\\?");
                if ((propertyAndValue.length >= 2) && "mediacontrolresuri".equalsIgnoreCase(propertyAndValue[0])) {
                    boolean stepping = false;
                    String[] params = propertyAndValue[1].split("&");
                    for (String param : params) {
                        String[] kvPair = param.split("=");
                        if (kvPair.length == 2) {
                            String key = kvPair[0];
                            String value = kvPair[1];
                            if ("playstate".equalsIgnoreCase(key)) {
                                controller.setPlayState(Boolean.valueOf(value));
                            }
                            if ("mediaaction".equalsIgnoreCase(key)) {
                                if ("stepforward".equalsIgnoreCase(value) || "stepbackward".equalsIgnoreCase(value)) {
                                    stepping = true;
                                }
                                controller.setCurrentAction(value);
                            }
                            if ("mediaspeed".equalsIgnoreCase(key)) {
                                controller.setSpeed(Double.valueOf(value));
                            }
                            if ("medialocation".equalsIgnoreCase(key)) {
                                if (stepping) {
                                    // location is offset from current
                                    controller.setLocation(controller.getLocation() + Double.valueOf(value));
                                } else {
                                    controller.setLocation(Double.valueOf(value));
                                }
                            }
                            // System.out.println("\t" + key + " = " + value);
                        }
                    }
                }
            }

            rep = rep.getNext();
        }

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        root.setTextString("name", controller.getName());
        root.setBoolean("playstate", controller.getPlayState());
        root.setTextString("mediaaction", controller.getCurrentAction());
        root.setStringArray("mediaactions", controller.getAllowedActions());
        root.setDouble("mediaspeed", controller.getSpeed());
        root.setDouble("medialocation", controller.getLocation());
        root.done();

        OcUtils.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

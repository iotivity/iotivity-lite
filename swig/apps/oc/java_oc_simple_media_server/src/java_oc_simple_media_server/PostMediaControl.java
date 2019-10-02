package java_oc_simple_media_server;

import java.util.List;

import org.iotivity.*;
import org.iotivity.oc.*;

public class PostMediaControl implements OCRequestHandler {

    private static final String URIEXP_KEY = "uriexp";

    private MediaController controller;

    public PostMediaControl(MediaController controller) {
        this.controller = controller;
    }

    @Override
    public void handler(OCRequest request, int interfaces) {
        // System.out.println("Inside the PostMediaControl RequestHandler");
        List<OCQueryValue> queryParams = OcUtils.getQueryValues(request);
        if (queryParams != null) {
            // Use query params
            String actionToUse = null;
            boolean useDefaultSpeed = true;
            boolean stepping = false;
            for (OCQueryValue param : queryParams) {
                String key = param.getKey();
                String value = param.getValue();
                if ("playstate".equalsIgnoreCase(key)) {
                    controller.setPlayState(Boolean.valueOf(value));
                }
                if ("mediaaction".equalsIgnoreCase(key)) {
                    if ("stepforward".equalsIgnoreCase(value) || "stepbackward".equalsIgnoreCase(value)) {
                        stepping = true;
                        // set step forward/backward default value
                        // default value will be overridden if
                        // medialocation is set
                        if ("stepforward".equalsIgnoreCase(value)) {
                            controller.setLocation(controller.getLocation() + 1000);
                        } else {
                            // stepbackward
                            controller.setLocation(controller.getLocation() - 1000);
                        }
                    }
                    actionToUse = value;
                }
                if ("mediaspeed".equalsIgnoreCase(key)) {
                    controller.setSpeed(Double.valueOf(value));
                    useDefaultSpeed = false;
                }
                if ("medialocation".equalsIgnoreCase(key)) {
                    if (stepping) {
                        // location is offset from current
                        controller.setLocation(controller.getLocation() + Double.valueOf(value));
                    } else {
                        controller.setLocation(Double.valueOf(value));
                    }
                }
                System.out.println("\t" + key + " = " + value);// TODO:comment
                                                               // out
            }

            if (actionToUse != null) {
                controller.setCurrentAction(actionToUse, useDefaultSpeed);
            }

        } else {
            // Use represenation
            OcRepresentation rep = new OcRepresentation(request.getRequestPayload());
            while (rep != null) {
                String uriexp = null;
                try {
                    if (URIEXP_KEY.equalsIgnoreCase(rep.getKey())) {
                        uriexp = rep.getString(URIEXP_KEY);
                        System.out.println("uriexp: " + uriexp);
                    }
                } catch (OcCborException e) {
                    System.err.println(e.getMessage());
                }

                if (uriexp != null) {
                    String actionToUse = null;
                    boolean useDefaultSpeed = true;
                    boolean stepping = false;
                    String[] params = uriexp.split("&");
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
                                    // set step forward/backward default value
                                    // default value will be overridden if
                                    // medialocation is set
                                    if ("stepforward".equalsIgnoreCase(value)) {
                                        controller.setLocation(controller.getLocation() + 1000);
                                    } else {
                                        // stepbackward
                                        controller.setLocation(controller.getLocation() - 1000);
                                    }
                                }
                                actionToUse = value;
                            }
                            if ("mediaspeed".equalsIgnoreCase(key)) {
                                controller.setSpeed(Double.valueOf(value));
                                useDefaultSpeed = false;
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
                    if (actionToUse != null) {
                        controller.setCurrentAction(actionToUse, useDefaultSpeed);
                    }
                }

                rep = rep.getNext();
            }
        }

        OcCborEncoder root = OcCborEncoder.createOcCborEncoder(OcCborEncoder.EncoderType.ROOT);
        GetMediaControl.encodeReturnValue(root, controller);
        root.done();

        OcUtils.sendResponse(request, OCStatus.OC_STATUS_CHANGED);
    }
}

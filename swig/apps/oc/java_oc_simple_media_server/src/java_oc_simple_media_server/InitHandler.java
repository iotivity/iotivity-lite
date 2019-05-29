package java_oc_simple_media_server;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.iotivity.*;
import org.iotivity.oc.*;

public class InitHandler implements OCMainInitHandler {

    private OcPlatform platform;
    private OcDevice device;
    private MediaController controller;
    private List<MediaResource> availableMedia = new ArrayList<>();
    private MediaResource activeMedia;

    static final private Map<Integer, String> interfaceMaskLookup = new HashMap<>();

    static {
        interfaceMaskLookup.put(OCInterfaceMask.BASELINE, "oic.if.baseline");
        interfaceMaskLookup.put(OCInterfaceMask.LL, "oic.if.ll");
        interfaceMaskLookup.put(OCInterfaceMask.B, "oic.if.b");
        interfaceMaskLookup.put(OCInterfaceMask.R, "oic.if.r");
        interfaceMaskLookup.put(OCInterfaceMask.RW, "oic.if.rw");
        interfaceMaskLookup.put(OCInterfaceMask.A, "oic.if.a");
        interfaceMaskLookup.put(OCInterfaceMask.S, "oic.if.s");
    }

    public InitHandler(OcPlatform platform) {
        this.platform = platform;
    }

    @Override
    public int initialize() {
        System.out.println("inside InitHandler.initialize()");

        int ret = platform.platformInit("Intel");
        if (ret >= 0) {
            device = new OcDevice("/oic/d", "oic.d.media.server", "SimpleMediaServer", "ocf.1.0.0", "ocf.res.1.0.0");
            ret |= platform.addDevice(device);
        }

        controller = new MediaController("Controller One");
        availableMedia.add(new MediaResource("Media One"));
        availableMedia.add(new MediaResource("Media Two"));

        OcUtils.setRandomPinHandler(new RandomPinHandler());
        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside InitHandler.registerResources()");

        String[] mediaControllerResourceTypes = new String[] { "oic.r.media.control" };
        int[] mediaControllerInterfaceMasks = new int[] { OCInterfaceMask.RW };

        OcResource mediaControlResource = new OcResource(device, "controller1", "/mediacontrol/1",
                mediaControllerResourceTypes, mediaControllerInterfaceMasks);
        mediaControlResource.setDefaultInterfaceMask(OCInterfaceMask.RW);
        mediaControlResource.setDiscoverable(true);
        mediaControlResource.setObservable(true);
        mediaControlResource.setPeriodicObservable(10);
        mediaControlResource.setGetRequestHandler(new GetMediaControl(controller));
        mediaControlResource.setPostRequestHandler(new PostMediaControl(controller));
        mediaControlResource.setPutRequestHandler(new PutMediaControl(controller));
        device.addResource(mediaControlResource);

        // TODO: add the media resources
    }

    @Override
    public void requestEntry() {
        System.out.println("inside InitHandler.requestEntry()");
        System.out.println("\tDeviceId = " + OCUuidUtil.uuidToString(device.getId()));
    }
}

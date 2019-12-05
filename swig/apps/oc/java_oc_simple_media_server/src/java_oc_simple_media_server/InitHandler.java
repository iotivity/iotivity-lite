package java_oc_simple_media_server;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javafx.stage.Stage;

import org.iotivity.*;
import org.iotivity.oc.*;

public class InitHandler implements OCMainInitHandler {

    private OcPlatform platform;
    private OcDevice device;
    private MediaController controller;
    private List<MediaResource> availableMedia = new ArrayList<>();
    private MediaResource activeMedia;

    private Stage primaryStage;

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

    public InitHandler(OcPlatform platform, Stage primaryStage) {
        this.platform = platform;
        this.primaryStage = primaryStage;
    }

    @Override
    public int initialize() {
        System.out.println("inside InitHandler.initialize()");

        int ret = platform.platformInit("Intel");
        if (ret >= 0) {
            device = new OcDevice("/oic/d", "oic.d.media.server", "SimpleMediaServer", "ocf.2.1.0", "ocf.res.1.0.0");
            ret |= platform.addDevice(device);
        }

        controller = new MediaController("Controller One", primaryStage);

        try {
            MediaResource media1 = new MediaResource("Infinite Zoom");
            media1.setUrl(ServerApp.class.getResource("/media/infinite-zoom.mp4").toURI().toString());
            availableMedia.add(media1);

            MediaResource media2 = new MediaResource("Landscape");
            media2.setUrl(ServerApp.class.getResource("/media/landscape.mp4").toURI().toString());
            availableMedia.add(media2);

            MediaResource media3 = new MediaResource("Jellyfish");
            media3.setUrl(ServerApp.class.getResource("/media/jellyfish.mp4").toURI().toString());
            availableMedia.add(media3);
        } catch (Exception e) {
            System.err.println("Error " + e);
        }

        OcUtils.setRandomPinHandler(new RandomPinHandler());
        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside InitHandler.registerResources()");

        String[] mediaControllerResourceTypes = new String[] { "oic.r.media.control" };
        int[] mediaControllerInterfaceMasks = new int[] { OCInterfaceMask.RW };

        String[] mediaResourceTypes = new String[] { "oic.r.media" };
        int[] mediaInterfaceMasks = new int[] { OCInterfaceMask.RW };

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

        OcResource mediaResource1 = new OcResource(device, "zoom", "/mediaresource/zoom/1", mediaResourceTypes,
                mediaInterfaceMasks);
        mediaResource1.setDefaultInterfaceMask(OCInterfaceMask.RW);
        mediaResource1.setDiscoverable(true);
        mediaResource1.setObservable(true);
        mediaResource1.setPeriodicObservable(10);
        mediaResource1.setGetRequestHandler(new GetMedia(availableMedia.get(0)));
        mediaResource1.setPostRequestHandler(new PostMedia(availableMedia.get(0), primaryStage));
        mediaResource1.setPutRequestHandler(new PutMedia(availableMedia.get(0), primaryStage));
        device.addResource(mediaResource1);

        OcResource mediaResource2 = new OcResource(device, "landscape", "/mediaresource/landscape/1", mediaResourceTypes,
                mediaInterfaceMasks);
        mediaResource2.setDefaultInterfaceMask(OCInterfaceMask.RW);
        mediaResource2.setDiscoverable(true);
        mediaResource2.setObservable(true);
        mediaResource2.setPeriodicObservable(10);
        mediaResource2.setGetRequestHandler(new GetMedia(availableMedia.get(1)));
        mediaResource2.setPostRequestHandler(new PostMedia(availableMedia.get(1), primaryStage));
        mediaResource2.setPutRequestHandler(new PutMedia(availableMedia.get(1), primaryStage));
        device.addResource(mediaResource2);

        OcResource mediaResource3 = new OcResource(device, "jellyfish", "/mediaresource/jellyfish/1", mediaResourceTypes,
                mediaInterfaceMasks);
        mediaResource3.setDefaultInterfaceMask(OCInterfaceMask.RW);
        mediaResource3.setDiscoverable(true);
        mediaResource3.setObservable(true);
        mediaResource3.setPeriodicObservable(10);
        mediaResource3.setGetRequestHandler(new GetMedia(availableMedia.get(2)));
        mediaResource3.setPostRequestHandler(new PostMedia(availableMedia.get(2), primaryStage));
        mediaResource3.setPutRequestHandler(new PutMedia(availableMedia.get(2), primaryStage));
        device.addResource(mediaResource3);
    }

    @Override
    public void requestEntry() {
        System.out.println("inside InitHandler.requestEntry()");
        System.out.println("\tDeviceId = " + OCUuidUtil.uuidToString(device.getId()));
    }
}

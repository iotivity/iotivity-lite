package java_oc_channel_change_server;

import java.util.HashMap;
import java.util.Map;

import org.iotivity.*;
import org.iotivity.oc.*;

public class InitHandler implements OCMainInitHandler {

    private OcPlatform platform;
    private OcDevice device;
    private ChannelChange channelChange;
    private Switch binarySwitch;
    private Audio audioControl;
    private MediaInput mediaInput;

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
            device = new OcDevice("/oic/d", "oic.d.tv", "ChannelChangeServer", "ocf.2.1.0",
                    "ocf.res.1.3.0,ocf.sh.1.3.0");
            ret |= platform.addDevice(device);
        }

        channelChange = new ChannelChange("Channel Change");
        binarySwitch = new Switch();
        audioControl = new Audio();
        mediaInput = new MediaInput();

        OcUtils.setRandomPinHandler(new RandomPinHandler());
        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside InitHandler.registerResources()");

        String[] channelChangeResourceTypes = new String[] { "oic.r.channelchange" };
        int[] channelChangeInterfaceMasks = new int[] { OCInterfaceMask.RW };

        String[] binarySwitchResourceTypes = new String[] { "oic.r.switch.binary" };
        int[] binarySwitchInterfaceMasks = new int[] { OCInterfaceMask.A };

        String[] audioResourceTypes = new String[] { "oic.r.audio" };
        int[] audioInterfaceMasks = new int[] { OCInterfaceMask.A };

        String[] mediaResourceTypes = new String[] { "oic.r.media.input" };
        int[] mediaInterfaceMasks = new int[] { OCInterfaceMask.A };

        OcResource channelChangeResource = new OcResource(device, "channelchange1", "/channelchange/1",
                channelChangeResourceTypes, channelChangeInterfaceMasks);
        channelChangeResource.setDefaultInterfaceMask(OCInterfaceMask.RW);
        channelChangeResource.setDiscoverable(true);
        channelChangeResource.setObservable(true);
        channelChangeResource.setPeriodicObservable(10);
        channelChangeResource.setGetRequestHandler(new GetChannelChange(channelChange));
        channelChangeResource.setPostRequestHandler(new PostChannelChange(channelChange));
        channelChangeResource.setPutRequestHandler(new PutChannelChange(channelChange));
        device.addResource(channelChangeResource);

        OcResource switchResource = new OcResource(device, "binaryswitch1", "/binaryswitch/1",
                binarySwitchResourceTypes, binarySwitchInterfaceMasks);
        switchResource.setDefaultInterfaceMask(OCInterfaceMask.A);
        switchResource.setDiscoverable(true);
        switchResource.setObservable(true);
        switchResource.setPeriodicObservable(10);
        switchResource.setGetRequestHandler(new GetSwitch(binarySwitch));
        switchResource.setPostRequestHandler(new PostSwitch(binarySwitch));
        switchResource.setPutRequestHandler(new PutSwitch(binarySwitch));
        device.addResource(switchResource);

        OcResource audioResource = new OcResource(device, "audio1", "/audio/1", audioResourceTypes,
                audioInterfaceMasks);
        audioResource.setDefaultInterfaceMask(OCInterfaceMask.A);
        audioResource.setDiscoverable(true);
        audioResource.setObservable(true);
        audioResource.setPeriodicObservable(10);
        audioResource.setGetRequestHandler(new GetAudio(audioControl));
        audioResource.setPostRequestHandler(new PostAudio(audioControl));
        audioResource.setPutRequestHandler(new PutAudio(audioControl));
        device.addResource(audioResource);

        OcResource mediaResource = new OcResource(device, "media1", "/media/1", mediaResourceTypes,
                mediaInterfaceMasks);
        mediaResource.setDefaultInterfaceMask(OCInterfaceMask.A);
        mediaResource.setDiscoverable(true);
        mediaResource.setObservable(true);
        mediaResource.setPeriodicObservable(10);
        mediaResource.setGetRequestHandler(new GetMediaInput(mediaInput));
        mediaResource.setPostRequestHandler(new PostMediaInput(mediaInput));
        mediaResource.setPutRequestHandler(new PutMediaInput(mediaInput));
        device.addResource(mediaResource);
    }

    @Override
    public void requestEntry() {
        System.out.println("inside InitHandler.requestEntry()");
        System.out.println("\tDeviceId = " + OCUuidUtil.uuidToString(device.getId()));
    }
}

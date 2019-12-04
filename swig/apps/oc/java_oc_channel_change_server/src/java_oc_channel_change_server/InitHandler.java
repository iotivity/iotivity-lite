package java_oc_channel_change_server;

import java.util.HashMap;
import java.util.Map;

import org.iotivity.*;
import org.iotivity.oc.*;

public class InitHandler implements OCMainInitHandler {

    private OcPlatform platform;
    private OcDevice device;
    private ChannelChange channelChange;

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
            device = new OcDevice("/oic/d", "oic.d.media.server", "ChannelChangeServer", "ocf.2.5.0", "ocf.res.1.3.0,ocf.sh.1.3.0");
            ret |= platform.addDevice(device);
        }

        channelChange = new ChannelChange("Channel Change");
        OcUtils.setRandomPinHandler(new RandomPinHandler());
        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside InitHandler.registerResources()");

        String[] channelChangeResourceTypes = new String[] { "oic.r.channelchange" };
        int[] channelChangeInterfaceMasks = new int[] { OCInterfaceMask.RW };

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
    }

    @Override
    public void requestEntry() {
        System.out.println("inside InitHandler.requestEntry()");
        System.out.println("\tDeviceId = " + OCUuidUtil.uuidToString(device.getId()));
    }
}

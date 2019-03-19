package java_oc_simple_server;

import org.iotivity.*;
import org.iotivity.oc.*;

public class MyInitHandler implements OCMainInitHandler {

    private OcPlatform platform;
    private OcDevice device;
    private Light light;

    public MyInitHandler(OcPlatform platform) {
        this.platform = platform;
    }

    @Override
    public int initialize() {
        System.out.println("inside MyInitHandler.initialize()");

        int ret = platform.platformInit("Intel");
        if (ret >= 0) {
            device = new OcDevice("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0", "ocf.res.1.0.0");
            ret |= platform.addDevice(device);
        }

        light = new Light("John's Light");

        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside MyInitHandler.registerResources()");

        String[] resourceTypes = new String[] { "core.light", "core.brightlight" };
        int[] interfaceMasks = new int[] { OCInterfaceMask.RW };

        OcResource resource = new OcResource(null, "/a/light", resourceTypes, interfaceMasks);

        resource.setDefaultInterfaceMask(OCInterfaceMask.RW);
        resource.setDiscoverable(true);
        resource.setObservable(true);
        resource.setPeriodicObservable(1);
        resource.setGetRequestHandler(new GetLight(light));
        resource.setPutRequestHandler(new PutLight(light));
        resource.setPostRequestHandler(new PostLight(light));

        device.addResource(resource);
    }

    @Override
    public void requestEntry() {
        System.out.println("inside MyInitHandler.requestEntry()");
    }
}

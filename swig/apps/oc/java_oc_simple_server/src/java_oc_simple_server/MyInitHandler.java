package java_oc_simple_server;

import java.util.HashMap;
import java.util.Map;

import org.iotivity.*;
import org.iotivity.oc.*;

public class MyInitHandler implements OCMainInitHandler {

    private OcPlatform platform;
    private OcDevice device;
    private Counter counter0;
    private Light light0;
    private Light light1;
    private Light light2;

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

    public MyInitHandler(OcPlatform platform) {
        this.platform = platform;
    }

    @Override
    public int initialize() {
        System.out.println("inside MyInitHandler.initialize()");

        int ret = platform.platformInit("Intel");
        if (ret >= 0) {
            device = new OcDevice("/oic/d", "oic.d.light", "Lamp", "ocf.2.5.0", "ocf.res.1.3.0,ocf.sh.1.3.0");
            ret |= platform.addDevice(device);
        }

        counter0 = new Counter("John's Counter");
        light0 = new Light("John's Light");
        light1 = new Light("Alice's Light");
        light2 = new Light("Bob's Light");

        OcUtils.setRandomPinHandler(new RandomPinHandler());
        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside MyInitHandler.registerResources()");

        String[] resourceTypes = new String[] { "oic.r.switch.binary", "oic.r.light.dimming" };
        int[] interfaceMasks = new int[] { OCInterfaceMask.RW };

        OcResource resource0 = new OcResource(device, "light0", "/a/light/0", resourceTypes, interfaceMasks);
        resource0.setDefaultInterfaceMask(OCInterfaceMask.RW);
        resource0.setDiscoverable(true);
        resource0.setObservable(true);
        resource0.setPeriodicObservable(1);
        resource0.setGetRequestHandler(new GetLight(light0));
        resource0.setPutRequestHandler(new PutLight(light0));
        resource0.setPostRequestHandler(new PostLight(light0));
        device.addResource(resource0);

        // for testing with client_collections_linux
        String[] lightResourceType = new String[] { "oic.r.light" };
        String[] counterResourceType = new String[] { "oic.r.counter" };
        String[] collectionResourceType = new String[] { "oic.wk.col" };

        int[] rIfaceMask = new int[] { OCInterfaceMask.R };
        int[] rwIfaceMask = new int[] { OCInterfaceMask.RW };

        OcResource lightResource = new OcResource(device, "lightbulb", "/light/1", lightResourceType, rwIfaceMask);
        lightResource.setDefaultInterfaceMask(OCInterfaceMask.RW);
        lightResource.setDiscoverable(true);
        lightResource.setObservable(true);
        lightResource.setPeriodicObservable(1);
        lightResource.setGetRequestHandler(new GetLight(light1));
        lightResource.setPutRequestHandler(new PutLight(light1));
        lightResource.setPostRequestHandler(new PostLight(light1));
        device.addResource(lightResource);

        OcResource lightResource2 = new OcResource(device, "lightbulb2", "/light/2", lightResourceType, rwIfaceMask);
        lightResource2.setDefaultInterfaceMask(OCInterfaceMask.RW);
        lightResource2.setDiscoverable(true);
        lightResource2.setObservable(true);
        lightResource2.setPeriodicObservable(1);
        lightResource2.setGetRequestHandler(new GetLight(light2));
        lightResource2.setPutRequestHandler(new PutLight(light2));
        lightResource2.setPostRequestHandler(new PostLight(light2));
        device.addResource(lightResource2);

        OcResource counterResource = new OcResource(device, "counter", "/count/1", counterResourceType, rIfaceMask);
        counterResource.setDefaultInterfaceMask(OCInterfaceMask.R);
        counterResource.setDiscoverable(true);
        counterResource.setObservable(true);
        counterResource.setPeriodicObservable(1);
        counterResource.setGetRequestHandler(new GetCounter(counter0));
        counterResource.setPostRequestHandler(new PostCounter(counter0));
        device.addResource(counterResource);

        OcCollection roomCollection = new OcCollection(device, "roomlights", "/lights", collectionResourceType, null,
                null);
        roomCollection.setDiscoverable(true);

        OcLink lightLink = new OcLink(lightResource);
        roomCollection.addLink(lightLink);

        OcLink lightLink2 = new OcLink(lightResource2);
        roomCollection.addLink(lightLink2);

        OcLink counterLink = new OcLink(counterResource);
        roomCollection.addLink(counterLink);

        device.addCollection(roomCollection);

        for (OcResource resource : device.getResources()) {
            System.out.println("Resource: " + resource.getName() + ", " + resource.getUri());
        }

        for (OcCollection collection : device.getCollections()) {
            System.out.println("Collection: " + collection.getName() + ", " + collection.getUri());
            for (OcLink link : collection.getLinks()) {
                System.out.println("\t" + link.getResource().getUri());
                System.out.println("\t" + link.getInstance());
                String[] relations = link.getRelations();
                System.out.print("\t[");
                for (String relation : relations) {
                    System.out.print(" " + relation);
                }
                System.out.println(" ]");
            }
            int[] masks = collection.getInterfaceMasks();
            System.out.print("\t[");
            for (Integer mask : masks) {
                System.out.print(" " + interfaceMaskLookup.get(mask));
            }
            System.out.println(" ]");
        }
    }

    @Override
    public void requestEntry() {
        System.out.println("inside MyInitHandler.requestEntry()");
        System.out.println("\tDeviceId = " + OCUuidUtil.uuidToString(device.getId()));
    }
}

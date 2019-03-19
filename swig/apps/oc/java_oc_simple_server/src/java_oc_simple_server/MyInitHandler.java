package java_oc_simple_server;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.iotivity.*;
import org.iotivity.oc.*;

public class MyInitHandler implements OCMainInitHandler {

    private OcPlatform platform;
    private OcDevice device;
    private Counter counter0;
    private Light light0;
    private Light light1;
    private Light light2;

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

        counter0 = new Counter("John's Counter");
        light0 = new Light("John's Light");
        light1 = new Light("Alice's Light");
        light2 = new Light("Bob's Light");

        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside MyInitHandler.registerResources()");

        String[] resourceTypes = new String[] { "core.light", "core.brightlight" };
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

        OcResource resource1 = new OcResource(device, "light1", "/a/light/1", resourceTypes, interfaceMasks);
        resource1.setDefaultInterfaceMask(OCInterfaceMask.RW);
        resource1.setDiscoverable(true);
        resource1.setObservable(true);
        resource1.setPeriodicObservable(1);
        resource1.setGetRequestHandler(new GetLight(light1));
        resource1.setPutRequestHandler(new PutLight(light1));
        resource1.setPostRequestHandler(new PostLight(light1));
        device.addResource(resource1);

        OcResource resource2 = new OcResource(device, "light2", "/a/light/2", resourceTypes, interfaceMasks);
        resource2.setDefaultInterfaceMask(OCInterfaceMask.RW);
        resource2.setDiscoverable(true);
        resource2.setObservable(true);
        resource2.setPeriodicObservable(1);
        resource2.setGetRequestHandler(new GetLight(light2));
        resource2.setPutRequestHandler(new PutLight(light2));
        resource2.setPostRequestHandler(new PostLight(light2));
        device.addResource(resource2);

        String[] collectionResourceTypes = new String[] { "oic.wk.col" };
        String[] supportedRts = resourceTypes;
        String[] mandatoryRts = new String[] { supportedRts[0] };
        OcCollection collection1 = new OcCollection(device, "2lights", "/a/lights", collectionResourceTypes,
                supportedRts, mandatoryRts);
        collection1.setDiscoverable(true);

        List<String> relations = new ArrayList(Arrays.asList(new String[] { "item" }));
        OcLink link1 = new OcLink(resource1, "1111", relations);
        collection1.addLink(link1);

        OcLink link2 = new OcLink(resource2, "2222", null);
        collection1.addLink(link2);

        // for testing with client_collections_linux
        String[] lightResourceType = new String[] { "oic.r.light" };
        String[] counterResourceType = new String[] { "oic.r.counter" };

        int[] rIfaceMask = new int[] { OCInterfaceMask.R };
        int[] rwIfaceMask = new int[] { OCInterfaceMask.RW };

        OcResource lightResource = new OcResource(device, "lightbulb", "/light/1", lightResourceType, rwIfaceMask);
        lightResource.setDefaultInterfaceMask(OCInterfaceMask.RW);
        lightResource.setDiscoverable(true);
        lightResource.setObservable(true);
        lightResource.setPeriodicObservable(1);
        lightResource.setGetRequestHandler(new GetLight(light0));
        lightResource.setPutRequestHandler(new PutLight(light0));
        lightResource.setPostRequestHandler(new PostLight(light0));
        device.addResource(lightResource);

        OcResource lightResource2 = new OcResource(device, "lightbulb", "/light/2", lightResourceType, rwIfaceMask);
        lightResource2.setDefaultInterfaceMask(OCInterfaceMask.RW);
        lightResource2.setDiscoverable(true);
        lightResource2.setObservable(true);
        lightResource2.setPeriodicObservable(1);
        lightResource2.setGetRequestHandler(new GetLight(light0));
        lightResource2.setPutRequestHandler(new PutLight(light0));
        lightResource2.setPostRequestHandler(new PostLight(light0));
        device.addResource(lightResource2);

        OcResource counterResource = new OcResource(device, "counter", "/count/1", counterResourceType, rIfaceMask);
        counterResource.setDefaultInterfaceMask(OCInterfaceMask.R);
        counterResource.setDiscoverable(true);
        counterResource.setObservable(true);
        counterResource.setPeriodicObservable(1);
        counterResource.setGetRequestHandler(new GetCounter(counter0));
        counterResource.setPostRequestHandler(new PostCounter(counter0));
        device.addResource(counterResource);

        OcCollection roomCollection = new OcCollection(device, "roomlights", "/lights", collectionResourceTypes, null,
                null);
        roomCollection.setDiscoverable(true);

        OcLink lightLink = new OcLink(lightResource);
        roomCollection.addLink(lightLink);

        OcLink lightLink2 = new OcLink(lightResource2);
        roomCollection.addLink(lightLink2);

        OcLink counterLink = new OcLink(counterResource);
        roomCollection.addLink(counterLink);

        device.addCollection(roomCollection);

        device.addCollection(collection1);

        for (OcResource resource : device.getResources()) {
            System.out.println("Resource: " + resource.getName() + ", " + resource.getUri());
        }

        for (OcCollection collection : device.getCollections()) {
            System.out.println("Collection: " + collection.getName() + ", " + collection.getUri());
            for (OcLink link : collection.getLinks()) {
                System.out.println("\t" + link.getResource().getUri());
                System.out.println("\t" + link.getInstance());
                System.out.println("\t" + link.getRelations());
            }
        }
    }

    @Override
    public void requestEntry() {
        System.out.println("inside MyInitHandler.requestEntry()");
    }
}

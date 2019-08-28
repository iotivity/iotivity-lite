package java_lite_simple_server;

import org.iotivity.*;

public class MyInitHandler implements OCMainInitHandler {
    @Override
    public int initialize() {
        System.out.println("inside MyInitHandler.initialize()");
        int ret = OCMain.initPlatform("Intel");
        ret |= OCMain.addDevice("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0", "ocf.res.1.0.0");
        ret |= OCMain.addDevice("/oic/d", "oic.d.refrigeration", "My fridge", "ocf.1.0.0", "ocf.res.1.0.0");
        ret |= OCMain.addDevice("/oic/d", "oic.d.thermostat", "My thermostat", "ocf.1.0.0", "ocf.res.1.0.0");

        // Initialize light device values
        Light.name = "John's Light";
        Light.power = 0;
        Light.state = false;

        Counter.name = "John's Counter";
        Counter.count = 0;

        // Initialize fridge device values
        Fridge.filter = 0;
        Fridge.rapidFreeze = false;
        Fridge.defrost = false;
        Fridge.rapidCool = false;

        // Initialize Thermostat
        Thermostat.temperature = 0.0;

        OCMain.setRandomPinHandler(new RandomPinHandler());
        return ret;
    }

    @Override
    public void registerResources() {
        // Setup resources for Device 0 'oic.d.light`
        System.out.println("inside MyInitHandler.registerResources()");
        OCResource resource = OCMain.newResource("", "/a/light", (short) 2, 0);
        OCMain.resourceBindResourceType(resource, "core.light");
        OCMain.resourceBindResourceType(resource, "core.brightlight");
        OCMain.resourceBindResourceInterface(resource, OCInterfaceMask.RW);
        OCMain.resourceSetDefaultInterface(resource, OCInterfaceMask.RW);
        OCMain.resourceSetDiscoverable(resource, true);
        OCMain.resourceSetPeriodicObservable(resource, 1);
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_GET, new GetLight());
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_PUT, new PutLight());
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_POST, new PostLight());
        OCMain.addResource(resource);

        // for running with client_collections_linux
        OCResource resource1 = OCMain.newResource("lightbulb", "/light/1", (short) 1, 0);
        OCMain.resourceBindResourceType(resource1, "oic.r.light");
        OCMain.resourceBindResourceInterface(resource1, OCInterfaceMask.RW);
        OCMain.resourceSetDefaultInterface(resource1, OCInterfaceMask.RW);
        OCMain.resourceSetDiscoverable(resource1, true);
        OCMain.resourceSetPeriodicObservable(resource1, 1);
        OCMain.resourceSetRequestHandler(resource1, OCMethod.OC_GET, new GetLight());
        OCMain.resourceSetRequestHandler(resource1, OCMethod.OC_PUT, new PutLight());
        OCMain.resourceSetRequestHandler(resource1, OCMethod.OC_POST, new PostLight());
        OCMain.addResource(resource1);

        OCResource resource2 = OCMain.newResource("counter", "/count/1", (short) 1, 0);
        OCMain.resourceBindResourceType(resource2, "oic.r.counter");
        OCMain.resourceBindResourceInterface(resource2, OCInterfaceMask.R);
        OCMain.resourceSetDefaultInterface(resource2, OCInterfaceMask.R);
        OCMain.resourceSetDiscoverable(resource2, true);
        OCMain.resourceSetPeriodicObservable(resource2, 1);
        OCMain.resourceSetRequestHandler(resource2, OCMethod.OC_GET, new GetCounter());
        OCMain.resourceSetRequestHandler(resource2, OCMethod.OC_POST, new PostCounter());
        OCMain.addResource(resource2);

        OCResource collection = OCMain.newCollection("roomlights", "/lights", (short) 1, (short) 0, (short) 0, 0);
        OCMain.resourceBindResourceType(collection, "oic.wk.col");
        OCMain.resourceSetDiscoverable(collection, true);

        OCLink link1 = OCMain.newLink(resource1);
        OCMain.collectionAddLink(collection, link1);

        OCLink link2 = OCMain.newLink(resource2);
        OCMain.collectionAddLink(collection, link2);
        OCMain.addCollection(collection);

        // Setup resources for Device 1 'oic.d.refrigeration`
        OCResource resource3 = OCMain.newResource("myfridge", "/fridge/1", (short) 1, 1);
        OCMain.resourceBindResourceType(resource3, "oic.r.refrigeration");
        OCMain.resourceBindResourceInterface(resource3, OCInterfaceMask.A);
        OCMain.resourceSetDefaultInterface(resource3, OCInterfaceMask.A);
        OCMain.resourceSetDiscoverable(resource3, true);
        OCMain.resourceSetPeriodicObservable(resource3, 1);
        OCMain.resourceSetRequestHandler(resource3, OCMethod.OC_GET, new GetFridge());
        OCMain.resourceSetRequestHandler(resource3, OCMethod.OC_POST, new PostFridge());
        OCMain.addResource(resource1);

        // Setup resources for Device 2 'oic.d.thermostat`
        OCResource resource4 = OCMain.newResource("tempsetter", "/temp/1", (short) 1, 2);
        OCMain.resourceBindResourceType(resource4, "oic.r.temperature");
        OCMain.resourceBindResourceInterface(resource4, OCInterfaceMask.A | OCInterfaceMask.S);
        OCMain.resourceSetDefaultInterface(resource4, OCInterfaceMask.A);
        OCMain.resourceSetDiscoverable(resource4, true);
        OCMain.resourceSetPeriodicObservable(resource4, 1);
        OCMain.resourceSetRequestHandler(resource4, OCMethod.OC_GET, new GetTemp());
        OCMain.resourceSetRequestHandler(resource4, OCMethod.OC_POST, new PostTemp());
        OCMain.addResource(resource4);
    }

    @Override
    public void requestEntry() {
        System.out.println("inside MyInitHandler.requestEntry()");
    }
}

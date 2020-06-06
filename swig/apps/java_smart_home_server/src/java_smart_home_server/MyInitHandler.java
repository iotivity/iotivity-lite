package java_smart_home_server;

import org.iotivity.*;

public class MyInitHandler implements OCMainInitHandler {

    private Switch binarySwitch = new Switch();
    private Temperature temperature = new Temperature();

    @Override
    public int initialize() {
        System.out.println("inside MyInitHandler.initialize()");
        int ret = OCMain.initPlatform("Intel");
        ret |= OCMain.addDevice("/oic/d", "oic.d.switch", "Temperature Sensor", "ocf.2.1.0",
                "ocf.res.1.3.0,ocf.sh.1.3.0");

        OCIntrospection.setIntrospectionData(0,
                SmartHomeIntrospectionData.getCborFileBytes("./assets/smart_home_introspection_data.cbor"));

        System.out.println("Introspection data set for device");

        OCMain.setRandomPinHandler(new RandomPinHandler());
        OCSoftwareUpdate.setImpl(new MySoftwareUpdateHandler());
        return ret;
    }

    @Override
    public void registerResources() {
        System.out.println("inside MyInitHandler.registerResources()");
        OCResource resource = OCMain.newResource("", "/switch", (short) 1, 0);
        OCMain.resourceBindResourceType(resource, "oic.r.switch.binary");
        OCMain.resourceBindResourceInterface(resource, OCInterfaceMask.A);
        OCMain.resourceSetDefaultInterface(resource, OCInterfaceMask.A);
        OCMain.resourceSetDiscoverable(resource, true);
        OCMain.resourceSetObservable(resource, true);
        OCMain.resourceSetPeriodicObservable(resource, 1);
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_GET, new GetSwitch(binarySwitch));
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_PUT, new PutSwitch(binarySwitch));
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_POST, new PostSwitch(binarySwitch));
        OCMain.addResource(resource);

        resource = OCMain.newResource("", "/temp", (short) 1, 0);
        OCMain.resourceBindResourceType(resource, "oic.r.temperature");
        OCMain.resourceBindResourceInterface(resource, OCInterfaceMask.A);
        OCMain.resourceBindResourceInterface(resource, OCInterfaceMask.S);
        OCMain.resourceSetDefaultInterface(resource, OCInterfaceMask.A);
        OCMain.resourceSetDiscoverable(resource, true);
        OCMain.resourceSetObservable(resource, true);
        OCMain.resourceSetPeriodicObservable(resource, 1);
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_GET, new GetTemperature(temperature));
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_PUT, new PutTemperature(temperature));
        OCMain.resourceSetRequestHandler(resource, OCMethod.OC_POST, new PostTemperature(temperature));
        OCMain.addResource(resource);
    }

    @Override
    public void requestEntry() {
        System.out.println("inside MyInitHandler.requestEntry()");
    }
}

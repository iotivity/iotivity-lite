package org.iotivity.multideviceserver;

import android.util.Log;

import org.iotivity.OCInterfaceMask;
import org.iotivity.OCMainInitHandler;
import org.iotivity.OCUuidUtil;
import org.iotivity.oc.OcDevice;
import org.iotivity.oc.OcPlatform;
import org.iotivity.oc.OcResource;
import org.iotivity.oc.OcUtils;

public class InitHandler implements OCMainInitHandler {

    private static final String TAG = InitHandler.class.getSimpleName();

    private ServerActivity activity;
    private OcPlatform ocPlatform;

    private OcDevice lightDevice;
    private OcDevice refrigeratorDevice;
    private OcDevice thermostatDevice;
    private OcDevice televisionDevice;

    private Light light;
    private Refrigerator refrigerator;
    private Thermostat thermostat;
    private Television television;

    public InitHandler(ServerActivity activity, OcPlatform ocPlatform) {
        this.activity = activity;
        this.ocPlatform = ocPlatform;
    }

    @Override
    public int initialize() {
        Log.d(TAG, "inside InitHandler.initialize()");
        int ret = ocPlatform.platformInit("Intel");
        if (ret >= 0) {
            // Create the devices and add them to the platform
            lightDevice = new OcDevice("/oic/d", "oic.d.light", "Lamp", "ocf.2.5.0", "ocf.res.1.3.0,ocf.sh.1.3.0");
            refrigeratorDevice = new OcDevice("/oic/d", "oic.d.refrigerator", "Refrigerator", "ocf.2.5.0", "ocf.res.1.3.0,ocf.sh.1.3.0");
            thermostatDevice = new OcDevice("/oic/d", "oic.d.thermostat", "Thermostat", "ocf.2.5.0", "ocf.res.1.3.0,ocf.sh.1.3.0");
            televisionDevice = new OcDevice("/oic/d", "oic.d.tv", "Television", "ocf.2.5.0", "ocf.res.1.3.0,ocf.sh.1.3.0");

            ret |= ocPlatform.addDevice(lightDevice);
            ret |= ocPlatform.addDevice(refrigeratorDevice);
            ret |= ocPlatform.addDevice(thermostatDevice);
            ret |= ocPlatform.addDevice(televisionDevice);

            light = new Light(lightDevice.getName());
            refrigerator = new Refrigerator(refrigeratorDevice.getName());
            thermostat = new Thermostat(thermostatDevice.getName());
            television = new Television(televisionDevice.getName());

        } else {
            Log.e(TAG, "Error in platformInit, return value = " + ret);
        }

        OcUtils.setRandomPinHandler(new RandomPinHandler(activity));
        return ret;
    }

    @Override
    public void registerResources() {
        Log.d(TAG, "inside InitHandler.registerResources()");

        // Create the resources and add them to their device

        String[] lightResourceTypes = new String[]{"oic.r.switch.binary", "oic.r.light.dimming"};
        int[] lightInterfaceMasks = new int[]{OCInterfaceMask.RW};

        String[] refrigeratorResourceTypes = new String[]{"oic.r.refrigeration"};
        int[] refrigeratorInterfaceMasks = new int[]{OCInterfaceMask.A};

        String[] thermostatResourceTypes = new String[]{"oic.r.temperature"};
        int[] thermostatInterfaceMasks = new int[]{OCInterfaceMask.A, OCInterfaceMask.S};

        String[] televisionResourceTypes = new String[]{"oic.r.media.input"};
        int[] televisionInterfaceMasks = new int[]{OCInterfaceMask.RW};

        if (lightDevice != null) {
            OcResource lightResource = new OcResource(lightDevice, "light", "/a/light", lightResourceTypes, lightInterfaceMasks);
            lightResource.setDefaultInterfaceMask(OCInterfaceMask.RW);
            lightResource.setDiscoverable(true);
            lightResource.setObservable(true);
            lightResource.setPeriodicObservable(1);
            lightResource.setGetRequestHandler(new GetLightRequestHandler(activity, light));
            lightResource.setPutRequestHandler(new PutLightRequestHandler(activity, light));
            lightResource.setPostRequestHandler(new PostLightRequestHandler(activity, light));
            lightDevice.addResource(lightResource);
        }

        if (refrigeratorDevice != null) {
            OcResource refrigeratorResource = new OcResource(refrigeratorDevice, "refrigerator", "/a/refrigerator", refrigeratorResourceTypes, refrigeratorInterfaceMasks);
            refrigeratorResource.setDefaultInterfaceMask(OCInterfaceMask.A);
            refrigeratorResource.setDiscoverable(true);
            refrigeratorResource.setObservable(true);
            refrigeratorResource.setPeriodicObservable(1);
            refrigeratorResource.setGetRequestHandler(new GetRefrigeratorRequestHandler(activity, refrigerator));
            refrigeratorResource.setPutRequestHandler(new PutRefrigeratorRequestHandler(activity, refrigerator));
            refrigeratorResource.setPostRequestHandler(new PostRefrigeratorRequestHandler(activity, refrigerator));
            refrigeratorDevice.addResource(refrigeratorResource);
        }

        if (thermostatDevice != null) {
            OcResource thermostatResource = new OcResource(thermostatDevice, "thermostat", "/a/thermostat", thermostatResourceTypes, thermostatInterfaceMasks);
            thermostatResource.setDefaultInterfaceMask(OCInterfaceMask.A);
            thermostatResource.setDiscoverable(true);
            thermostatResource.setObservable(true);
            thermostatResource.setPeriodicObservable(1);
            thermostatResource.setGetRequestHandler(new GetThermostatRequestHandler(activity, thermostat));
            thermostatResource.setPutRequestHandler(new PutThermostatRequestHandler(activity, thermostat));
            thermostatResource.setPostRequestHandler(new PostThermostatRequestHandler(activity, thermostat));
            thermostatDevice.addResource(thermostatResource);
        }

        if (televisionDevice != null) {
            OcResource televisionResource = new OcResource(televisionDevice, "television", "/a/television", televisionResourceTypes, televisionInterfaceMasks);
            televisionResource.setDefaultInterfaceMask(OCInterfaceMask.RW);
            televisionResource.setDiscoverable(true);
            televisionResource.setObservable(true);
            televisionResource.setPeriodicObservable(1);
            televisionResource.setGetRequestHandler(new GetTelevisionRequestHandler(activity, this.television));
            televisionResource.setPutRequestHandler(new PutTelevisionRequestHandler(activity, this.television));
            televisionResource.setPostRequestHandler(new PostTelevisionRequestHandler(activity, this.television));
            televisionDevice.addResource(televisionResource);
        }
    }

    @Override
    public void requestEntry() {
        Log.d(TAG, "inside InitHandler.requestEntry()");
        Log.d(TAG, "Light DeviceId = " + ((lightDevice != null) ? OCUuidUtil.uuidToString(lightDevice.getId()) : "null"));
        Log.d(TAG, "Refrigerator DeviceId = " + ((refrigeratorDevice != null) ? OCUuidUtil.uuidToString(refrigeratorDevice.getId()) : "null"));
        Log.d(TAG, "Thermostat DeviceId = " + ((thermostatDevice != null) ? OCUuidUtil.uuidToString(thermostatDevice.getId()) : "null"));
        Log.d(TAG, "Television DeviceId = " + ((televisionDevice != null) ? OCUuidUtil.uuidToString(televisionDevice.getId()) : "null"));
    }
}

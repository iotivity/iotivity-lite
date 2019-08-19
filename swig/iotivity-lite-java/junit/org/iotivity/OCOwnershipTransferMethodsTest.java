package org.iotivity;

import org.junit.*;
import static org.junit.Assert.*;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class OCOwnershipTransferMethodsTest {
    
    // wait times chosen arbitrarily they can be adjusted if needed.
    private final int WAIT_TIME_SHORT = 3;
    private final int WAIT_TIME_MED = 10;
    private final int WAIT_TIME_LONG = 30;
    
    private static CountDownLatch requestEntryExecuted;
//    private static CountDownLatch getLightExecuted;
//    
//    public static class BinarySwitch {
//        public static boolean value;
//    }
//    
//    private static OCRequestHandler getLight = new OCRequestHandler() {
//        
//        @Override
//        public void handler(OCRequest request, int interfaces) {
//            System.out.println("Inside the MultiDevice GetLight RequestHandler");
//            System.out.println("GET:");
//            CborEncoder root = OCRep.beginRootObject();
//            switch (interfaces) {
//            case OCInterfaceMask.BASELINE: {
//                OCMain.processBaselineInterface(request.getResource());
//                /* fall through */
//            }
//            case OCInterfaceMask.RW: {
//                OCRep.setBoolean(root, "value", BinarySwitch.value);
//                break;
//            }
//            default:
//                break;
//            }
//            OCRep.endRootObject();
//            OCMain.sendResponse(request, OCStatus.OC_STATUS_OK);
//            getLightExecuted.countDown();
//        }
//    };
//    
//    private static OCRequestHandler putPostLight = new OCRequestHandler() {
//        
//        @Override
//        public void handler(OCRequest request, int interfaces) {
//            System.out.println("Inside the MultiDevice GetLight RequestHandler");
//            System.out.println("PUT/POST:");
//        }
//    };
    
    private static OCMainInitHandler init = new OCMainInitHandler() {
        @Override
        public int initialize() {
            System.out.println("inside MultiDevice initilize()");
            int ret = OCMain.initPlatform("Desktop Computer");
            assertEquals(0, ret);
            ret |= OCMain.addDevice("/oic/d", "oic.d.computer.desktop", "Test OBT", "ocf.1.0.0", "ocf.res.1.0.0");
            assertEquals(0, ret);
            ret |= OCMain.addDevice("/oic/d", "oic.d.light", "Test Light", "ocf.1.0.0", "ocf.res.1.0.0");
            assertEquals(0, ret);
//            ret |= OCMain.addDevice("/oic/d", "oic.d.lightingcontrol", "Test Light Control", "ocf.1.0.0", "ocf.res.1.0.0");
//            assertEquals(0, ret);
//            BinarySwitch.value = true;
            return ret;
        }

        @Override
        public void registerResources() {
//            System.out.println("inside MultiDevice registerResources()");
//            OCResource resource = OCMain.newResource("", "/light/switch", (short) 1, 1);
//            assertNotNull(resource);
//            OCMain.resourceBindResourceType(resource, "oic.r.switch.binary");
//            OCMain.resourceBindResourceInterface(resource, OCInterfaceMask.RW);
//            OCMain.resourceSetDefaultInterface(resource, OCInterfaceMask.RW);
//            OCMain.resourceSetDiscoverable(resource, true);
//            OCMain.resourceSetPeriodicObservable(resource, 1);
//            OCMain.resourceSetRequestHandler(resource, OCMethod.OC_GET, getLight);
//            OCMain.resourceSetRequestHandler(resource, OCMethod.OC_PUT, putPostLight);
//            OCMain.resourceSetRequestHandler(resource, OCMethod.OC_POST, putPostLight);
//            assertTrue(OCMain.addResource(resource));
        }

        @Override
        public void requestEntry() {
            System.out.println("inside MultiDevice requestEntry()");
            assertNotEquals(-1, OCObt.init());
            requestEntryExecuted.countDown();
        }
    };

    @Before
    public void setup() {
        System.out.println("setup");
        String creds_path = "./unit_test_device_creds/";
        
        // Make sure the creds directory exists
        java.io.File directory = new java.io.File(creds_path);
        if (!directory.exists()) {
            directory.mkdir();
        }
        // This onboards and runs the code we expect the security related files to be cleared each run.
        for(java.io.File file: directory.listFiles()) { 
            if (!file.isDirectory()) { 
                file.delete();
            }
        }
        
        assertEquals(0,  OCStorage.storageConfig(directory.getPath()));

        requestEntryExecuted = new CountDownLatch(1);
        assertTrue(OCMain.mainInit(init) >= 0);
    }
    
    @After
    public void teardown() {
        System.out.println("teardown");
        OCMain.mainShutdown();
        OCObt.shutdown();
    }
    
    
    /*
     * 1. Discover unowned devices
     * 1a. verify server is unowned
     * 2. Perform **Just works OTM**
     * 3. Discover owned devices
     * 3a. verify server is now owned
     */
    @Test
    public void justWorksOTM() {
        try {
            System.out.println("justWorksOTM");
            assertTrue(requestEntryExecuted.await(WAIT_TIME_SHORT, TimeUnit.SECONDS));

            CountDownLatch discoverUnownedDevicesHandlerExecuted = new CountDownLatch(1);
            assertEquals(0 , OCObt.discoverUnownedDevices(new OCObtDiscoveryHandler() {
                @Override
                public void handler(OCUuid uuid, OCEndpoint endpoints) {
                    if (uuid.equals(OCCoreRes.getDeviceId(1))) {
                        discoverUnownedDevicesHandlerExecuted.countDown();
                    }
                }
            }));
            assertTrue(discoverUnownedDevicesHandlerExecuted.await(WAIT_TIME_MED, TimeUnit.SECONDS));
            CountDownLatch justWorksOtmHandlerExecuted = new CountDownLatch(1);
            assertEquals(0 , OCObt.performJustWorksOtm(OCCoreRes.getDeviceId(1), new OCObtDeviceStatusHandler() {
                @Override
                public void handler(OCUuid uuid, int status) {
                    assertEquals(0, status);
                    justWorksOtmHandlerExecuted.countDown();
                }
            }));
            assertTrue(justWorksOtmHandlerExecuted.await(WAIT_TIME_MED, TimeUnit.SECONDS));
            
            CountDownLatch discoverOwnedDevicesHandlerExecuted = new CountDownLatch(1);
            assertEquals(0 , OCObt.discoverOwnedDevices(new OCObtDiscoveryHandler() {
                @Override
                public void handler(OCUuid uuid, OCEndpoint endpoints) {
                    if (uuid.equals(OCCoreRes.getDeviceId(1))) {
                        discoverOwnedDevicesHandlerExecuted.countDown();
                    }
                }
            }));
            assertTrue(discoverOwnedDevicesHandlerExecuted.await(WAIT_TIME_MED, TimeUnit.SECONDS));

        } catch (InterruptedException e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    public class RandomPinHandler implements OCRandomPinHandler {
        public String pin;
        @Override
        public void handler(String pin) {
            this.pin = pin;
        }
    }
    
    /*
     * 1. Discover unowned devices
     * 1a. verify server is unowned
     * 2. Request Random Pin
     * 2a. Perform **Random Pin OTM** using requested randomPin
     * 3. Discover owned devices
     * 3a. verify server is now owned
     */
    @Test
    public void randomPinOTM() {
        try {
            assertTrue(requestEntryExecuted.await(WAIT_TIME_SHORT, TimeUnit.SECONDS));

            CountDownLatch discoverUnownedDevicesHandlerExecuted = new CountDownLatch(1);
            assertEquals(0 , OCObt.discoverUnownedDevices(new OCObtDiscoveryHandler() {
                @Override
                public void handler(OCUuid uuid, OCEndpoint endpoints) {
                    if (uuid.equals(OCCoreRes.getDeviceId(1))) {
                        discoverUnownedDevicesHandlerExecuted.countDown();
                    }
                }
            }));
            assertTrue(discoverUnownedDevicesHandlerExecuted.await(WAIT_TIME_MED, TimeUnit.SECONDS));

            RandomPinHandler testRandomPinHandler = new RandomPinHandler();
            OCMain.setRandomPinHandler(testRandomPinHandler);
            
            CountDownLatch requestRandomPinExecuted = new CountDownLatch(1);
            OCObt.requestRandomPin(OCCoreRes.getDeviceId(1), new OCObtDeviceStatusHandler() {
                
                @Override
                public void handler(OCUuid uuid, int status) {
                    assertEquals(OCCoreRes.getDeviceId(1), uuid);
                    System.out.println(OCUuidUtil.uuidToString(uuid));
                    assertEquals(0, status);
                    requestRandomPinExecuted.countDown();
                }
            });
            assertTrue(requestRandomPinExecuted.await(WAIT_TIME_MED, TimeUnit.SECONDS));
            CountDownLatch randomPinOtmHandlerExecuted = new CountDownLatch(1);
            assertEquals(0 , OCObt.performRandomPinOtm(OCCoreRes.getDeviceId(1), testRandomPinHandler.pin, testRandomPinHandler.pin.length(), new OCObtDeviceStatusHandler() {
                @Override
                public void handler(OCUuid uuid, int status) {
                    assertEquals(0, status);
                    randomPinOtmHandlerExecuted.countDown();
                }
            }));
            assertTrue(randomPinOtmHandlerExecuted.await(WAIT_TIME_MED, TimeUnit.SECONDS));
            
            CountDownLatch discoverOwnedDevicesHandlerExecuted = new CountDownLatch(1);
            assertEquals(0 , OCObt.discoverOwnedDevices(new OCObtDiscoveryHandler() {
                @Override
                public void handler(OCUuid uuid, OCEndpoint endpoints) {
                    if (uuid.equals(OCCoreRes.getDeviceId(1))) {
                        discoverOwnedDevicesHandlerExecuted.countDown();
                    }
                }
            }));
            assertTrue(discoverOwnedDevicesHandlerExecuted.await(WAIT_TIME_MED, TimeUnit.SECONDS));

        } catch (InterruptedException e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }
}

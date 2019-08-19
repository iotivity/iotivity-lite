package org.iotivity;

import org.junit.*;
import static org.junit.Assert.*;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class OCOwnershipTransferMethodsTest {
    
    // wait times chosen arbitrarily they can be adjusted if needed.
    private final int WAIT_TIME_SHORT = 3;
    private final int WAIT_TIME_MED = 10;
    // private final int WAIT_TIME_LONG = 30;
    
    private static CountDownLatch requestEntryExecuted;
    private static OCMainInitHandler init = new OCMainInitHandler() {
        @Override
        public int initialize() {
            int ret = OCMain.initPlatform("Desktop Computer");
            assertEquals(0, ret);
            ret |= OCMain.addDevice("/oic/d", "oic.d.computer.desktop", "Test OBT", "ocf.1.0.0", "ocf.res.1.0.0");
            assertEquals(0, ret);
            ret |= OCMain.addDevice("/oic/d", "oic.d.light", "Test Light", "ocf.1.0.0", "ocf.res.1.0.0");
            assertEquals(0, ret);
            return ret;
        }

        @Override
        public void registerResources() {
        }

        @Override
        public void requestEntry() {
            assertNotEquals(-1, OCObt.init());
            requestEntryExecuted.countDown();
        }
    };

    @Before
    public void setup() {
        String creds_path = "./otm_test_creds/";
        
        // Make sure the creds directory exists
        java.io.File directory = new java.io.File(creds_path);
        if (!directory.exists()) {
            directory.mkdir();
        }
        // we clear all the security related files each run.
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
                    assertEquals(0, status);
                    requestRandomPinExecuted.countDown();
                }
            });
            assertTrue(requestRandomPinExecuted.await(WAIT_TIME_MED, TimeUnit.SECONDS));
            CountDownLatch randomPinOtmHandlerExecuted = new CountDownLatch(1);
            assertEquals(0 , OCObt.performRandomPinOtm(OCCoreRes.getDeviceId(1), testRandomPinHandler.pin, new OCObtDeviceStatusHandler() {
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

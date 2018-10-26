package org.iotivity;

import static org.junit.Assert.*;

import org.junit.Test;


public class OCResourceTest {
    @Test
    public void testDevice() {
        OCResource r = new OCResource();
        assertNotNull(r);
        r.setDevice(0);
        assertEquals(0, r.getDevice());
        r.setDevice(1);
        assertEquals(1,  r.getDevice());
    }

    @Test
    public void testName() {
        OCResource r = new OCResource();
        assertNotNull(r);
        r.setName("FooBar");
        assertEquals("FooBar", r.getName());
    }

    @Test
    public void testUri() {
        OCResource r = new OCResource();
        assertNotNull(r);
        r.setUri("/foo/bar");
        assertEquals("/foo/bar", r.getUri());
    }

    @Test
    public void testTypes() {
        OCResource r = new OCResource();
        assertNotNull(r);
        String[] typesArray = {"oic.r.light.dimming", "oic.r.switch.binary"};
        r.setTypes(typesArray);
        org.junit.Assert.assertArrayEquals(typesArray, r.getTypes());
    }

    @Test
    public void testInterfaces() {
        OCResource r = new OCResource();
        assertNotNull(r);
        r.setInterfaces(OCInterfaceMask.RW);
        assertEquals(OCInterfaceMask.RW, r.getInterfaces());
    }

    @Test
    public void testDefaultInterface() {
        OCResource r = new OCResource();
        assertNotNull(r);
        r.setDefaultInterface(OCInterfaceMask.BASELINE);
        assertEquals(OCInterfaceMask.BASELINE, r.getDefaultInterface());
    }

    @Test
    public void testProperties(){
        OCResource r = new OCResource();
        assertNotNull(r);
        fail("setProperties implementation crashes VM");
        r.setProperties((OCResourcePropertiesMask.OC_DISCOVERABLE | OCResourcePropertiesMask.OC_OBSERVABLE));
        assertTrue((r.getProperties() & OCResourcePropertiesMask.OC_DISCOVERABLE) == OCResourcePropertiesMask.OC_DISCOVERABLE);
        assertTrue((r.getProperties() & OCResourcePropertiesMask.OC_OBSERVABLE) == OCResourcePropertiesMask.OC_OBSERVABLE);
        assertFalse((r.getProperties() & OCResourcePropertiesMask.OC_PERIODIC) == OCResourcePropertiesMask.OC_PERIODIC);
        assertFalse((r.getProperties() & OCResourcePropertiesMask.OC_SECURE) == OCResourcePropertiesMask.OC_SECURE);
    }

    @Test
    public void testObservePeriodSeconds() {
        OCResource r = new OCResource();
        assertNotNull(r);
        r.setObservePeriodSeconds(42);
        assertEquals(42, r.getObservePeriodSeconds());
    }
}

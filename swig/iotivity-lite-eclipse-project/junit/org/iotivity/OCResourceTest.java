package org.iotivity;

import static org.junit.Assert.*;

import org.junit.Test;


public class OCResourceTest {
    static {
        System.loadLibrary("iotivity-lite-java");
    }

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
        //TODO properly encode/decode the OCResource oc_string_array_t types.
        //r.setTypes(value);
        // failure purposely done till the setTypes/getProperties methods are updated with non SWIG type values.
        fail("Not yet implemented");
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
        //TODO properly encode/decode the OCResource oc_resource_properties_t types.
        //r.setTypes(value);
        // failure purposely done till the setProperties/getProperties methods are updated with non SWIG type values.
        fail("Not yet implemented");
    }

    @Test
    public void testObservePeriodSeconds() {
        OCResource r = new OCResource();
        assertNotNull(r);
        r.setObservePeriodSeconds(42);
        assertEquals(42, r.getObservePeriodSeconds());
    }
}

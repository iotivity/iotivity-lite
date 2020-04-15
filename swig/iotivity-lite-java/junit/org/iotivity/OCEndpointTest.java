package org.iotivity;

import static org.junit.Assert.*;

import org.junit.Test;

public class OCEndpointTest {

    @Test
    public void testStringToEndpoint() {
        String[] uri = new String[1];
        // IPV4 with port and uri
        OCEndpoint ep = null;
        try {
            ep = OCEndpointUtil.stringToEndpoint("coaps://10.211.55.3:56789/a/light", uri);
        } catch (OCEndpointParseException e) {
            e.printStackTrace();
            fail("stringToEndpoint threw exception when it was not expected.");
        }
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV4, ep.getFlags() & OCTransportFlags.IPV4);
        assertEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertNotEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(56789, ep.getAddr().getIpv4().getPort());
        assertEquals("/a/light", uri[0]);
        assertArrayEquals(new short[]{10, 211, 55, 3}, ep.getAddr().getIpv4().getAddress());
        OCEndpointUtil.freeEndpoint(ep);
        assertEquals(0, OCEndpoint.getCPtr(ep));

        // IPV6
        try {
            ep = OCEndpointUtil.stringToEndpoint("coap://[ff02::158]", uri);
        } catch (OCEndpointParseException e) {
            e.printStackTrace();
            fail("stringToEndpoint threw exception when it was not expected.");
        }
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV6, (ep.getFlags() & OCTransportFlags.IPV6));
        assertNotEquals(OCTransportFlags.SECURED, (ep.getFlags() & OCTransportFlags.SECURED));
        assertNotEquals(OCTransportFlags.TCP, (ep.getFlags() & OCTransportFlags.TCP));
        assertEquals(5683, ep.getAddr().getIpv6().getPort());
        assertNull(uri[0]);
        assertArrayEquals(new short[]{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58},
                ep.getAddr().getIpv6().getAddress());
        OCEndpointUtil.freeEndpoint(ep);
        assertEquals(0, OCEndpoint.getCPtr(ep));

        // IPV6 with uri
        try {
            ep = OCEndpointUtil.stringToEndpoint("coaps://[ff02::158]/a/light", uri);
        } catch (OCEndpointParseException e) {
            e.printStackTrace();
            fail("stringToEndpoint threw exception when it was not expected.");
        }
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV6, (ep.getFlags() & OCTransportFlags.IPV6));
        assertEquals(OCTransportFlags.SECURED, (ep.getFlags() & OCTransportFlags.SECURED));
        assertNotEquals(OCTransportFlags.TCP, (ep.getFlags() & OCTransportFlags.TCP));
        assertEquals(5684, ep.getAddr().getIpv6().getPort());
        assertEquals("/a/light", uri[0]);
        assertArrayEquals(new short[]{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58},
                ep.getAddr().getIpv6().getAddress());
        OCEndpointUtil.freeEndpoint(ep);
        assertEquals(0, OCEndpoint.getCPtr(ep));

        // IPV6 with port and uri
        try {
            ep = OCEndpointUtil.stringToEndpoint("coaps://[fe80::12]:2439/a/light", uri);
        } catch (OCEndpointParseException e) {
            e.printStackTrace();
            fail("stringToEndpoint threw exception when it was not expected.");
        }
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV6, (ep.getFlags() & OCTransportFlags.IPV6));
        assertEquals(OCTransportFlags.SECURED, (ep.getFlags() & OCTransportFlags.SECURED));
        assertNotEquals(OCTransportFlags.TCP, (ep.getFlags() & OCTransportFlags.TCP));
        assertEquals(2439, ep.getAddr().getIpv6().getPort());
        assertEquals("/a/light", uri[0]);
        assertArrayEquals(new short[]{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12},
                ep.getAddr().getIpv6().getAddress());
        OCEndpointUtil.freeEndpoint(ep);
        assertEquals(0, OCEndpoint.getCPtr(ep));
    }

    // The tests will fail on Windows. It does not yet support dns lookup.
    @Test
    public void testStringToEndpoint_dns_lookup() {
        String[] uri = new String[1];
        // dns lookup
        OCEndpoint ep = null;
        try {
            ep = OCEndpointUtil.stringToEndpoint("coap://openconnectivity.org", uri);
        } catch (OCEndpointParseException e) {
            e.printStackTrace();
            fail("stringToEndpoint threw exception when it was not expected.");
        }
        assertNotNull(ep);
        assertTrue(OCTransportFlags.IPV4 == (ep.getFlags() & OCTransportFlags.IPV4) ||
                OCTransportFlags.IPV6 == (ep.getFlags() & OCTransportFlags.IPV6));
        assertNotEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertNotEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(5683, ep.getAddr().getIpv4().getPort());
        assertNull(uri[0]);
        OCEndpointUtil.freeEndpoint(ep);
        assertEquals(0, OCEndpoint.getCPtr(ep));

        // dns lookup with uri
        try {
            ep = OCEndpointUtil.stringToEndpoint("coap://openconnectivity.org/alpha", uri);
        } catch (OCEndpointParseException e) {
            e.printStackTrace();
            fail("stringToEndpoint threw exception when it was not expected.");
        }
        assertNotNull(ep);
        assertTrue(OCTransportFlags.IPV4 == (ep.getFlags() & OCTransportFlags.IPV4) ||
                OCTransportFlags.IPV6 == (ep.getFlags() & OCTransportFlags.IPV6));
        assertNotEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertNotEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(5683, ep.getAddr().getIpv4().getPort());
        assertEquals("/alpha", uri[0]);
        OCEndpointUtil.freeEndpoint(ep);
        assertEquals(0, OCEndpoint.getCPtr(ep));

        // dns lookup with port and uri
        try {
            ep = OCEndpointUtil.stringToEndpoint("coaps://openconnectivity.org:3456/alpha", uri);
        } catch (OCEndpointParseException e) {
            e.printStackTrace();
            fail("stringToEndpoint threw exception when it was not expected.");
        }
        assertNotNull(ep);
        assertTrue(OCTransportFlags.IPV4 == (ep.getFlags() & OCTransportFlags.IPV4) ||
                OCTransportFlags.IPV6 == (ep.getFlags() & OCTransportFlags.IPV6));
        assertEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertNotEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(3456, ep.getAddr().getIpv4().getPort());
        assertEquals("/alpha", uri[0]);
        OCEndpointUtil.freeEndpoint(ep);
        assertEquals(0, OCEndpoint.getCPtr(ep));
    }

    // The tests will fail on Windows. It does not yet support tcp.
    @Test
    public void testStringToEndpoint_tcp() {
        String[] uri = new String[1];
        // IPv4 over tcp and uri
        OCEndpoint ep = null;
        try {
            ep = OCEndpointUtil.stringToEndpoint("coaps+tcp://10.211.55.3/a/light", uri);
        } catch (OCEndpointParseException e) {
            e.printStackTrace();
            fail("stringToEndpoint threw exception when it was not expected.");
        }
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV4, ep.getFlags() & OCTransportFlags.IPV4);
        assertEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(5684, ep.getAddr().getIpv4().getPort());
        assertEquals("/a/light", uri[0]);
        assertArrayEquals(new short[]{10, 211, 55, 3}, ep.getAddr().getIpv4().getAddress());
        OCEndpointUtil.freeEndpoint(ep);
        assertEquals(0, OCEndpoint.getCPtr(ep));

        // IPv4 over tcp and port
        try {
            ep = OCEndpointUtil.stringToEndpoint("coap+tcp://1.2.3.4:2568", uri);
        } catch (OCEndpointParseException e) {
            e.printStackTrace();
            fail("stringToEndpoint threw exception when it was not expected.");
        }
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV4, (ep.getFlags() & OCTransportFlags.IPV4));
        assertNotEquals(OCTransportFlags.SECURED, (ep.getFlags() & OCTransportFlags.SECURED));
        assertEquals(OCTransportFlags.TCP, (ep.getFlags() & OCTransportFlags.TCP));
        assertEquals(2568, ep.getAddr().getIpv4().getPort());
        assertNull(uri[0]);
        assertArrayEquals(new short[]{1, 2, 3, 4}, ep.getAddr().getIpv4().getAddress());
        OCEndpointUtil.freeEndpoint(ep);
        assertEquals(0, OCEndpoint.getCPtr(ep));

        // IPv6 over tcp  
        try {
            ep = OCEndpointUtil.stringToEndpoint("coap+tcp://[ff02::158]", uri);
        } catch (OCEndpointParseException e) {
            e.printStackTrace();
            fail("stringToEndpoint threw exception when it was not expected.");
        }
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV6, (ep.getFlags() & OCTransportFlags.IPV6));
        assertNotEquals(OCTransportFlags.SECURED, (ep.getFlags() & OCTransportFlags.SECURED));
        assertEquals(OCTransportFlags.TCP, (ep.getFlags() & OCTransportFlags.TCP));
        assertEquals(5683, ep.getAddr().getIpv6().getPort());
        assertNull(uri[0]);
        assertArrayEquals(new short[]{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58},
                ep.getAddr().getIpv6().getAddress());
        OCEndpointUtil.freeEndpoint(ep);
        assertEquals(0, OCEndpoint.getCPtr(ep));

        // IPv6 over tcp with uri
        try {
            ep = OCEndpointUtil.stringToEndpoint("coaps+tcp://[ff02::158]/a/light", uri);
        } catch (OCEndpointParseException e) {
            e.printStackTrace();
            fail("stringToEndpoint threw exception when it was not expected.");
        }
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV6, (ep.getFlags() & OCTransportFlags.IPV6));
        assertEquals(OCTransportFlags.SECURED, (ep.getFlags() & OCTransportFlags.SECURED));
        assertEquals(OCTransportFlags.TCP, (ep.getFlags() & OCTransportFlags.TCP));
        assertEquals(5684, ep.getAddr().getIpv6().getPort());
        assertEquals("/a/light", uri[0]);
        assertArrayEquals(new short[]{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58},
                ep.getAddr().getIpv6().getAddress());
        OCEndpointUtil.freeEndpoint(ep);
        assertEquals(0, OCEndpoint.getCPtr(ep));

        // IPv6 over tcp with port and uri 
        try {
            ep = OCEndpointUtil.stringToEndpoint("coaps+tcp://[fe80::12]:2439/a/light", uri);
        } catch (OCEndpointParseException e) {
            e.printStackTrace();
            fail("stringToEndpoint threw exception when it was not expected.");
        }
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV6, (ep.getFlags() & OCTransportFlags.IPV6));
        assertEquals(OCTransportFlags.SECURED, (ep.getFlags() & OCTransportFlags.SECURED));
        assertEquals(OCTransportFlags.TCP, (ep.getFlags() & OCTransportFlags.TCP));
        assertEquals(2439, ep.getAddr().getIpv6().getPort());
        assertEquals("/a/light", uri[0]);
        assertArrayEquals(new short[]{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12},
                ep.getAddr().getIpv6().getAddress());
        OCEndpointUtil.freeEndpoint(ep);
        assertEquals(0, OCEndpoint.getCPtr(ep));
    }

    // The tests will fail on Windows. It does not yet support tcp or dns lookup.
    @Test
    public void testStringToEndpoint_tcp_and_dns_lookup() {
        String[] uri = new String[1];
        // dns lookup over tcp with port
        OCEndpoint ep = null;
        try {
            ep = OCEndpointUtil.stringToEndpoint("coaps+tcp://openconnectivity.org:3456", uri);
        } catch (OCEndpointParseException e) {
            e.printStackTrace();
            fail("stringToEndpoint threw exception when it was not expected.");
        }
        assertNotNull(ep);
        assertTrue(OCTransportFlags.IPV4 == (ep.getFlags() & OCTransportFlags.IPV4) ||
                OCTransportFlags.IPV6 == (ep.getFlags() & OCTransportFlags.IPV6));
        assertEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(3456, ep.getAddr().getIpv4().getPort());
        assertNull(uri[0]);
        OCEndpointUtil.freeEndpoint(ep);
        assertEquals(0, OCEndpoint.getCPtr(ep));
    }

    @Test
    public void test_throw_exception_on_setDi_when_endpoint_null() {
        // must call OCRandom.init to initialize the random number for generateUuid
        OCRandom.init();
        try {
            OCUuid testUuid = OCUuidUtil.generateUuid();
            OCEndpointUtil.setDi(null, testUuid);
            fail("The call to setDi when endpoint is null should thow an exception.");
        } catch (Exception e) {
            assertEquals( e.getClass(), NullPointerException.class);
            assertEquals(e.getMessage(), "OCEndpoint cannot be null.");
        }
        // Restore random number to un-initialized state for other tests
        OCRandom.destroy();
    }

    @Test
    public void test_throw_exception_on_setDi_when_di_null() {
        try {
            String[] uri = new String[1];
            // IPV4 with port and uri
            OCEndpoint ep = OCEndpointUtil.stringToEndpoint("coaps://10.211.55.3:56789/a/light", uri);
            assertNotNull(ep);
            OCEndpointUtil.setDi(ep, null);
            fail("The call to setDi when di is null should thow an exception.");
        } catch (Exception e) {
            assertEquals( e.getClass(), NullPointerException.class);
            assertEquals(e.getMessage(), "OCUuid cannot be null.");
        }
    }

    @Test
    public void test_throw_parse_exception_stringToEndpoint() {
        String[] uri = new String[1];
        OCEndpoint ep = null;
        try {
            ep = OCEndpointUtil.stringToEndpoint("", uri);
            fail("The call stringToEndpoint should throw an exception");
        } catch (Exception e) {
            assertEquals(OCEndpointParseException.class, e.getClass());
            assertEquals("The \"\" string cannot be parsed.", e.getMessage());
        }

        try {
            // will fail does not have `://`
            ep = OCEndpointUtil.stringToEndpoint("coaps+tcp", uri);
            fail("The call stringToEndpoint should throw an exception");
        } catch (Exception e) {
            assertEquals(OCEndpointParseException.class, e.getClass());
            assertEquals("The \"coaps+tcp\" string cannot be parsed.", e.getMessage());
        }

        try {
            ep = OCEndpointUtil.stringToEndpoint("foobar", uri);
            fail("The call stringToEndpoint should throw an exception");
        } catch (Exception e) {
            assertEquals(OCEndpointParseException.class, e.getClass());
            assertEquals("The \"foobar\" string cannot be parsed.", e.getMessage());
        }
        try {
            ep = OCEndpointUtil.stringToEndpoint(null, uri);
            fail("The call stringToEndpoint should throw an exception");
        } catch (Exception e) {
            assertEquals(OCEndpointParseException.class, e.getClass());
            assertEquals("The (null) string cannot be parsed.", e.getMessage());
        }
        assertNull(ep);
    }
}

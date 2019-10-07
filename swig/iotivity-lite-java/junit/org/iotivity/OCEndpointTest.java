package org.iotivity;

import static org.junit.Assert.*;

import org.junit.Test;

public class OCEndpointTest {

    @Test
    public void testStringToEndpoint() {
        String[] uri = new String[1];
        // IPV4 with port and uri
        OCEndpoint ep = OCEndpointUtil.stringToEndpoint("coaps://10.211.55.3:56789/a/light", uri);
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV4, ep.getFlags() & OCTransportFlags.IPV4);
        assertEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertNotEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(56789, ep.getAddr().getIpv4().getPort());
        assertEquals("/a/light", uri[0]);
        assertArrayEquals(new short[]{10, 211, 55, 3}, ep.getAddr().getIpv4().getAddress());
        OCEndpointUtil.freeEndpoint(ep);

        // IPV6
        ep = OCEndpointUtil.stringToEndpoint("coap://[ff02::158]", uri);
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV6, (ep.getFlags() & OCTransportFlags.IPV6));
        assertNotEquals(OCTransportFlags.SECURED, (ep.getFlags() & OCTransportFlags.SECURED));
        assertNotEquals(OCTransportFlags.TCP, (ep.getFlags() & OCTransportFlags.TCP));
        assertEquals(5683, ep.getAddr().getIpv6().getPort());
        assertNull(uri[0]);
        assertArrayEquals(new short[]{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58},
                ep.getAddr().getIpv6().getAddress());
        OCEndpointUtil.freeEndpoint(ep);

        // IPV6 with uri
        ep = OCEndpointUtil.stringToEndpoint("coaps://[ff02::158]/a/light", uri);
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV6, (ep.getFlags() & OCTransportFlags.IPV6));
        assertEquals(OCTransportFlags.SECURED, (ep.getFlags() & OCTransportFlags.SECURED));
        assertNotEquals(OCTransportFlags.TCP, (ep.getFlags() & OCTransportFlags.TCP));
        assertEquals(5684, ep.getAddr().getIpv6().getPort());
        assertEquals("/a/light", uri[0]);
        assertArrayEquals(new short[]{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58},
                ep.getAddr().getIpv6().getAddress());
        OCEndpointUtil.freeEndpoint(ep);

        // IPV6 with port and uri
        ep = OCEndpointUtil.stringToEndpoint("coaps://[fe80::12]:2439/a/light", uri);
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV6, (ep.getFlags() & OCTransportFlags.IPV6));
        assertEquals(OCTransportFlags.SECURED, (ep.getFlags() & OCTransportFlags.SECURED));
        assertNotEquals(OCTransportFlags.TCP, (ep.getFlags() & OCTransportFlags.TCP));
        assertEquals(2439, ep.getAddr().getIpv6().getPort());
        assertEquals("/a/light", uri[0]);
        assertArrayEquals(new short[]{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12},
                ep.getAddr().getIpv6().getAddress());
        OCEndpointUtil.freeEndpoint(ep);
    }

    // The tests will fail on Windows. It does not yet support dns lookup.
    @Test
    public void testStringToEndpoint_dns_lookup() {
        String[] uri = new String[1];
        // dns lookup
        OCEndpoint ep = OCEndpointUtil.stringToEndpoint("coap://openconnectivity.org", uri);
        assertNotNull(ep);
        assertTrue(OCTransportFlags.IPV4 == (ep.getFlags() & OCTransportFlags.IPV4) ||
                OCTransportFlags.IPV6 == (ep.getFlags() & OCTransportFlags.IPV6));
        assertNotEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertNotEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(5683, ep.getAddr().getIpv4().getPort());
        assertNull(uri[0]);
        OCEndpointUtil.freeEndpoint(ep);

        // dns lookup with uri
        ep = OCEndpointUtil.stringToEndpoint("coap://openconnectivity.org/alpha", uri);
        assertNotNull(ep);
        assertTrue(OCTransportFlags.IPV4 == (ep.getFlags() & OCTransportFlags.IPV4) ||
                OCTransportFlags.IPV6 == (ep.getFlags() & OCTransportFlags.IPV6));
        assertNotEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertNotEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(5683, ep.getAddr().getIpv4().getPort());
        assertEquals("/alpha", uri[0]);
        OCEndpointUtil.freeEndpoint(ep);

        // dns lookup with port and uri
        ep = OCEndpointUtil.stringToEndpoint("coaps://openconnectivity.org:3456/alpha", uri);
        assertNotNull(ep);
        assertTrue(OCTransportFlags.IPV4 == (ep.getFlags() & OCTransportFlags.IPV4) ||
                OCTransportFlags.IPV6 == (ep.getFlags() & OCTransportFlags.IPV6));
        assertEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertNotEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(3456, ep.getAddr().getIpv4().getPort());
        assertEquals("/alpha", uri[0]);
        OCEndpointUtil.freeEndpoint(ep);
    }

    // The tests will fail on Windows. It does not yet support tcp.
    @Test
    public void testStringToEndpoint_tcp() {
        String[] uri = new String[1];
        // IPv4 over tcp and uri
        OCEndpoint ep = OCEndpointUtil.stringToEndpoint("coaps+tcp://10.211.55.3/a/light", uri);
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV4, ep.getFlags() & OCTransportFlags.IPV4);
        assertEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(5684, ep.getAddr().getIpv4().getPort());
        assertEquals("/a/light", uri[0]);
        assertArrayEquals(new short[]{10, 211, 55, 3}, ep.getAddr().getIpv4().getAddress());
        OCEndpointUtil.freeEndpoint(ep);

        // IPv4 over tcp and port
        ep = OCEndpointUtil.stringToEndpoint("coap+tcp://1.2.3.4:2568", uri);
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV4, (ep.getFlags() & OCTransportFlags.IPV4));
        assertNotEquals(OCTransportFlags.SECURED, (ep.getFlags() & OCTransportFlags.SECURED));
        assertEquals(OCTransportFlags.TCP, (ep.getFlags() & OCTransportFlags.TCP));
        assertEquals(2568, ep.getAddr().getIpv4().getPort());
        assertNull(uri[0]);
        assertArrayEquals(new short[]{1, 2, 3, 4}, ep.getAddr().getIpv4().getAddress());
        OCEndpointUtil.freeEndpoint(ep);

        // IPv6 over tcp  
        ep = OCEndpointUtil.stringToEndpoint("coap+tcp://[ff02::158]", uri);
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV6, (ep.getFlags() & OCTransportFlags.IPV6));
        assertNotEquals(OCTransportFlags.SECURED, (ep.getFlags() & OCTransportFlags.SECURED));
        assertEquals(OCTransportFlags.TCP, (ep.getFlags() & OCTransportFlags.TCP));
        assertEquals(5683, ep.getAddr().getIpv6().getPort());
        assertNull(uri[0]);
        assertArrayEquals(new short[]{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58},
                ep.getAddr().getIpv6().getAddress());
        OCEndpointUtil.freeEndpoint(ep);

        // IPv6 over tcp with uri
        ep = OCEndpointUtil.stringToEndpoint("coaps+tcp://[ff02::158]/a/light", uri);
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV6, (ep.getFlags() & OCTransportFlags.IPV6));
        assertEquals(OCTransportFlags.SECURED, (ep.getFlags() & OCTransportFlags.SECURED));
        assertEquals(OCTransportFlags.TCP, (ep.getFlags() & OCTransportFlags.TCP));
        assertEquals(5684, ep.getAddr().getIpv6().getPort());
        assertEquals("/a/light", uri[0]);
        assertArrayEquals(new short[]{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58},
                ep.getAddr().getIpv6().getAddress());
        OCEndpointUtil.freeEndpoint(ep);

        // IPv6 over tcp with port and uri 
        ep = OCEndpointUtil.stringToEndpoint("coaps+tcp://[fe80::12]:2439/a/light", uri);
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV6, (ep.getFlags() & OCTransportFlags.IPV6));
        assertEquals(OCTransportFlags.SECURED, (ep.getFlags() & OCTransportFlags.SECURED));
        assertEquals(OCTransportFlags.TCP, (ep.getFlags() & OCTransportFlags.TCP));
        assertEquals(2439, ep.getAddr().getIpv6().getPort());
        assertEquals("/a/light", uri[0]);
        assertArrayEquals(new short[]{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12},
                ep.getAddr().getIpv6().getAddress());
        OCEndpointUtil.freeEndpoint(ep);
    }

    // The tests will fail on Windows. It does not yet support tcp or dns lookup.
    @Test
    public void testStringToEndpoint_tcp_and_dns_lookup() {
        String[] uri = new String[1];
        // dns lookup over tcp with port
        OCEndpoint ep = OCEndpointUtil.stringToEndpoint("coaps+tcp://openconnectivity.org:3456", uri);
        assertNotNull(ep);
        assertTrue(OCTransportFlags.IPV4 == (ep.getFlags() & OCTransportFlags.IPV4) ||
                OCTransportFlags.IPV6 == (ep.getFlags() & OCTransportFlags.IPV6));
        assertEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(3456, ep.getAddr().getIpv4().getPort());
        assertNull(uri[0]);
        OCEndpointUtil.freeEndpoint(ep);
    }

    @Test
    public void test_throw_exception_on_setDi_when_endpoint_null() {
        try {
            OCUuid testUuid = OCUuidUtil.generateUuid();
            OCEndpointUtil.setDi(null, testUuid);
            fail("The call to setDi when endpoint is null should thow an exception.");
        } catch (Exception e) {
            assertEquals( e.getClass(), NullPointerException.class);
            assertEquals(e.getMessage(), "OCEndpoint cannot be null.");
        }
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
}

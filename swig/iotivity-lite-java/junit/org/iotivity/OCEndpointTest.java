package org.iotivity;

import static org.junit.Assert.*;

import org.junit.Test;

public class OCEndpointTest {

    @Test
    public void testStringToEndpoint() {
        String[] uri = new String[1];
        OCEndpoint ep = OCEndpointUtil.stringToEndpoint("coaps://10.211.55.3:56789/a/light", uri);
        assertNotNull(ep);
        assertEquals(OCTransportFlags.IPV4, ep.getFlags() & OCTransportFlags.IPV4);
        assertEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertNotEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(56789, ep.getAddr().getIpv4().getPort());
        assertEquals("/a/light", uri[0]);
        assertArrayEquals(new short[]{10, 211, 55, 3}, ep.getAddr().getIpv4().getAddress());
        OCEndpointUtil.freeEndpoint(ep);

        ep = OCEndpointUtil.stringToEndpoint("coap://openconnectivity.org", uri);
        assertNotNull(ep);
        assertTrue(OCTransportFlags.IPV4 == (ep.getFlags() & OCTransportFlags.IPV4) ||
                   OCTransportFlags.IPV6 == (ep.getFlags() & OCTransportFlags.IPV6));
        assertNotEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertNotEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(5683, ep.getAddr().getIpv4().getPort());
        assertEquals("", uri[0]);
        assertArrayEquals(new short[]{10, 211, 55, 3}, ep.getAddr().getIpv4().getAddress());
        OCEndpointUtil.freeEndpoint(ep);

        ep = OCEndpointUtil.stringToEndpoint("coap://openconnectivity.org/alpha", uri);
        assertNotNull(ep);
        assertTrue(OCTransportFlags.IPV4 == (ep.getFlags() & OCTransportFlags.IPV4) ||
                   OCTransportFlags.IPV6 == (ep.getFlags() & OCTransportFlags.IPV6));
        assertNotEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertNotEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(5683, ep.getAddr().getIpv4().getPort());
        assertEquals("/alpha", uri[0]);
        assertArrayEquals(new short[]{10, 211, 55, 3}, ep.getAddr().getIpv4().getAddress());
        OCEndpointUtil.freeEndpoint(ep);

        ep = OCEndpointUtil.stringToEndpoint("coaps://openconnectivity.org:3456/alpha", uri);
        assertNotNull(ep);
        assertTrue(OCTransportFlags.IPV4 == (ep.getFlags() & OCTransportFlags.IPV4) ||
                   OCTransportFlags.IPV6 == (ep.getFlags() & OCTransportFlags.IPV6));
        assertEquals(OCTransportFlags.SECURED, ep.getFlags() & OCTransportFlags.SECURED);
        assertNotEquals(OCTransportFlags.TCP, ep.getFlags() & OCTransportFlags.TCP);
        assertEquals(3456, ep.getAddr().getIpv4().getPort());
        assertEquals("/alpha", uri[0]);
        assertArrayEquals(new short[]{10, 211, 55, 3}, ep.getAddr().getIpv4().getAddress());
        OCEndpointUtil.freeEndpoint(ep);
    }

}

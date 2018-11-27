package org.iotivity;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

public class OCMainTest {
    @Test
    public void testGetQueryValues() {
        OCRequest request = new OCRequest();
        request.setQuery("field1=value1&field2=value2&field3=value3");
        request.setQuery_len("field1=value1&field2=value2&field3=value3".length());
        List<OCQueryValue> qv = OCMain.getQueryValues(request);
        assertNotNull(qv);
        assertEquals(3, qv.size());
        System.out.println(">>>>>> " + qv.get(0).key + " : " + qv.get(0).value);
        assertTrue(qv.get(0).getKey().equals("field1"));
        assertTrue(qv.get(0).getValue().equals("value1"));
        assertTrue(qv.get(1).getKey().equals("field2"));
        assertTrue(qv.get(1).getValue().equals("value2"));
        assertTrue(qv.get(2).getKey().equals("field3"));
        assertTrue(qv.get(2).getValue().equals("value3"));

    }
}

package org.iotivity;

import static org.junit.Assert.*;

import org.iotivity.OCRepresentation.OCValue;
import org.junit.Test;

public class OCRepresentationTest {
    @Test
    public void testType() {
        OCRepresentation req = new OCRepresentation();
        assertNotNull(req);
        req.setType(OCType.OC_REP_INT);
        assertEquals(OCType.OC_REP_INT, req.getType());
    }

    @Test
    public void testNext() {
        OCRepresentation req1 = new OCRepresentation();
        OCRepresentation req2 = new OCRepresentation();
        OCRepresentation req3 = new OCRepresentation();
        assertNotNull(req1);
        assertNotNull(req2);
        assertNotNull(req3);
        req1.setName("one");
        req2.setName("two");
        req3.setName("three");
        req1.setNext(req2);
        req1.getNext().setNext(req3);
        OCRepresentation r = req1;
        assertEquals("one", r.getName());
        r = r.getNext();
        assertNotNull(r);
        assertEquals("two", r.getName());
        r = r.getNext();
        assertNotNull(r);
        assertEquals("three", r.getName());
        r = r.getNext();
        assertNull(r);
    }

    @Test
    public void testName() {
        OCRepresentation req = new OCRepresentation();
        assertNotNull(req);
        req.setName("Sam");
        assertEquals("Sam", req.getName());
    }

    @Test
    public void testValue() {
        OCRepresentation req = new OCRepresentation();
        assertNotNull(req);
        OCValue v = new OCValue();
        v.setString("happy dog");
        req.setValue(v);
        assertEquals("happy dog", req.getValue().getString());
    }

    @Test
    public void testValueInteger() {
        OCValue v = new OCValue();
        assertNotNull(v);
        v.setInteger(1010101);
        assertEquals(1010101, v.getInteger());
        v.setInteger(42);
        assertEquals(42, v.getInteger());
        v.setInteger(0);
        assertEquals(0, v.getInteger());
        v.setInteger(-54);
        assertEquals(-54, v.getInteger());
    }

    @Test
    public void testValueBool() {
        OCValue v = new OCValue();
        assertNotNull(v);
        v.setBool(true);
        assertTrue(v.getBool());
        v.setBool(false);
        assertFalse(v.getBool());
    }

    @Test
    public void testValueDouble() {
        OCValue v = new OCValue();
        assertNotNull(v);
        v.setDouble(3.14159265359);
        assertEquals(3.14159265359, v.getDouble(), 0.0000000001);
        v.setDouble(1.618033988749895);
        assertEquals(1.618033988749895, v.getDouble(), 0.000000000000001);
        v.setDouble(-1.618033988749895);
        assertEquals(-1.618033988749895, v.getDouble(), 0.00000000000001);
        v.setDouble(-3.14159265359);
        assertEquals(-3.14159265359, v.getDouble(), 0.0000000001);
    }

    @Test
    public void testValueString() {
        OCValue v = new OCValue();
        assertNotNull(v);
        v.setString("more");
        assertEquals("more", v.getString());
        v.setString("");
        assertEquals("", v.getString());
    }

    @Test
    public void testValueArray() {
        fail("Not yet implemented");
    }

    @Test
    public void testValueObject() {
        OCMain.repNewBuffer(1024);

        /*
         * Create an OCRepresentation with the following
         *  {
         *     "a": 1,
         *     "b": false,
         *     "c": "three"
         *   }
         */
        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetInt(root, "a", 1);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetBoolean(root, "b", false);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(root, "c", "three");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        OCValue v = new OCValue();
        assertNotNull(v);
        v.setObject(rep);

        // access directly using the OCValue
        OCRepresentation outObject = v.getObject();
        assertNotNull(outObject);
        assertEquals(OCType.OC_REP_INT, outObject.getType());
        assertTrue(outObject.getName().equals("a"));
        assertEquals(1, outObject.getValue().getInteger());

        outObject = outObject.getNext();
        assertNotNull(outObject);
        assertTrue(outObject.getName().equals("b"));
        assertEquals(OCType.OC_REP_BOOL, outObject.getType());
        assertFalse(outObject.getValue().getBool());
        
        outObject = outObject.getNext();
        assertNotNull(outObject);
        assertTrue(outObject.getName().equals("c"));
        assertEquals(OCType.OC_REP_STRING, outObject.getType());
        assertEquals("three", outObject.getValue().getString());
        
        // Access values indirectly using repGet functions
        int a[] = new int[1];
        OCMain.repGetInt(v.getObject(), "a", a);
        assertEquals(1, a[0]);
        boolean b[] = new boolean[1];
        OCMain.repGetBoolean(v.getObject(), "b", b);
        assertEquals(false, b[0]);
        String c[] = new String[1];
        OCMain.repGetString(v.getObject(), "c", c);
        assertEquals("three", c[0]);
        OCMain.repDeleteBuffer();
    }

    @Test
    public void testValueObjectArray() {
        fail("Not yet implemented");
    }

    @Test
    public void testRepInt() {
        OCMain.repNewBuffer(1024);

        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        assertNotNull(root);
        OCMain.repSetInt(root, "ultimat_answer", 42);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        //OCMain.repSetPool(new OCMemoryBuffer());
        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        int[] outValue = new int[1];
        OCMain.repGetInt(rep, "ultimat_answer", outValue);
        assertEquals(42, outValue[0]);
        OCMain.repDeleteBuffer();
    }

    @Test
    public void testRepBoolean() {
        OCMain.repNewBuffer(1024);

        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        assertNotNull(root);
        OCMain.repSetBoolean(root, "true_flag", true);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        //OCMain.repSetPool(new OCMemoryBuffer());
        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        boolean[] outValue = new boolean[1];
        OCMain.repGetBoolean(rep, "true_flag", outValue);
        assertEquals(true, outValue[0]);
        OCMain.repDeleteBuffer();
    }

    @Test
    public void testRepDouble() {
        OCMain.repNewBuffer(1024);
        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        assertNotNull(root);
        OCMain.repSetDouble(root, "pi", 3.14);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        //OCMain.repSetPool(new OCMemoryBuffer());
        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        double[] outValue = new double[1];
        OCMain.repGetDouble(rep, "pi", outValue);
        assertEquals(3.14, outValue[0], 0.001);
        OCMain.repDeleteBuffer();
    }

    @Test
    public void testRepString() {
        OCMain.repNewBuffer(1024);

        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        assertNotNull(root);
        OCMain.repSetTextString(root, "hello", "world");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(root, "empty", "");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        //OCMain.repSetPool(new OCMemoryBuffer());
        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        String[] outValue = new String[1];
        assertTrue(OCMain.repGetString(rep, "hello", outValue));
        assertTrue(outValue[0].equals("world"));
        assertTrue(OCMain.repGetString(rep, "empty", outValue));
        assertTrue(outValue[0].equals(""));
        OCMain.repDeleteBuffer();
    }

    @Test
    public void testRepBooleanArray() {
        OCMain.repNewBuffer(1024);

        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        assertNotNull(root);
        boolean barray[] = {false, false, true, false, false};
        OCMain.repSetBooleanArray(root, "flips", barray);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        //OCMain.repSetPool(new OCMemoryBuffer());
        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        boolean outValue[] = OCMain.repGetBooleanArray(rep, "flips");
        assertNotNull(outValue);
        assertEquals(barray.length, outValue.length);
        assertArrayEquals(barray, outValue);
        OCMain.repDeleteBuffer();
    }

    @Test
    public void testRepDoubleArray() {
        OCMain.repNewBuffer(1024);

        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        assertNotNull(root);
        double mathConstants[] = {3.1415926535, 2.71828,  1.4142135, 1.618033};
        OCMain.repSetDoubleArray(root, "math_constants", mathConstants);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        //OCMain.repSetPool(new OCMemoryBuffer());
        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        double outValue[] = OCMain.repGetDoubleArray(rep, "math_constants");
        assertNotNull(outValue);
        assertEquals(mathConstants.length, outValue.length);
        assertArrayEquals(mathConstants, outValue, 0.000001);
        OCMain.repDeleteBuffer();
    }

    @Test
    public void testRepIntArray() {
        OCMain.repNewBuffer(1024);

        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        assertNotNull(root);
        int fib[] = {1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89};
        OCMain.repSetIntArray(root, "fibonacci", fib);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        //OCMain.repSetPool(new OCMemoryBuffer());
        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        int outValue[] = OCMain.repGetIntArray(rep, "fibonacci");
        assertNotNull(outValue);
        assertEquals(fib.length, outValue.length);
        assertArrayEquals(fib, outValue);
        OCMain.repDeleteBuffer();
    }

    @Test
    public void testRepStringArray() {
        OCMain.repNewBuffer(1024);

        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        assertNotNull(root);
        String lorem_ipsum[] = {"Lorem", "ipsum", "dolor", "sit", "amet",
                                "consectetur", "adipiscing", "elit.", "Sed",
                                "nec", "feugiat", "odio.", "Donec."};
        OCMain.repSetStringArray(root, "lorem_ipsum", lorem_ipsum);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        String outValue[] = OCMain.repGetStringArray(rep, "lorem_ipsum");
        assertNotNull(outValue);
        assertEquals(lorem_ipsum.length, outValue.length);
        assertArrayEquals(lorem_ipsum, outValue);
        OCMain.repDeleteBuffer();
    }

    @Test
    public void testRepByteString() {
        OCMain.repNewBuffer(1024);

        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        assertNotNull(root);
        byte fibBytes[] = {0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x13, 0x21, 0x34, 0x55, (byte)0x89};
        OCMain.repSetByteString(root, "fib_bytes", fibBytes);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        //OCMain.repSetPool(new OCMemoryBuffer());
        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        byte outValue[] = OCMain.repGetByteString(rep, "fib_bytes");
        assertNotNull(outValue);
        assertEquals(fibBytes.length, outValue.length);
        assertArrayEquals(fibBytes, outValue);
        OCMain.repDeleteBuffer();
    }
    
    @Test
    public void testRepObject() {
        OCMain.repNewBuffer(1024);

        /*
         * {
         *   "my_object": {
         *     "a": 1,
         *     "b": false,
         *     "c": "three"
         *   }
         * }
         */
        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        CborEncoder myObject = OCMain.repSetObject(root, "my_object");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetInt(myObject, "a", 1);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetBoolean(myObject, "b", false);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(myObject, "c", "three");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repCloseObject(root, myObject);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        //OCMain.repSetPool(new OCMemoryBuffer());
        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        OCRepresentation myObjectOut = OCMain.repGetObject(rep, "my_object");
        assertNotNull(myObjectOut);

        int a[] = new int[1];
        OCMain.repGetInt(myObjectOut, "a", a);
        assertEquals(1, a[0]);
        boolean b[] = new boolean[1];
        OCMain.repGetBoolean(myObjectOut, "b", b);
        assertEquals(false, b[0]);
        String c[] = new String[1];
        OCMain.repGetString(myObjectOut, "c", c);
        assertEquals("three", c[0]);

        OCMain.repDeleteBuffer();
    }
}

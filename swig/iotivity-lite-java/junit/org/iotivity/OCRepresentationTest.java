package org.iotivity;

import static org.junit.Assert.*;

import org.iotivity.OCRepresentation.*;
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
        OCMain.repNewBuffer(1024);

        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        assertNotNull(root);
        long fib[] = {1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89};
        OCMain.repSetIntArray(root, "fibonacci", fib);
        assertEquals(0, OCMain.repGetCborErrno());
        boolean barray[] = {false, false, true, false, false};
        OCMain.repSetBooleanArray(root, "flips", barray);
        assertEquals(0, OCMain.repGetCborErrno());
        double mathConstants[] = {3.1415926535, 2.71828,  1.4142135, 1.618033};
        OCMain.repSetDoubleArray(root, "math_constants", mathConstants);
        assertEquals(0, OCMain.repGetCborErrno());
        String lorem_ipsum[] = {"Lorem", "ipsum", "dolor", "sit", "amet",
                "consectetur", "adipiscing", "elit.", "Sed",
                "nec", "feugiat", "odio.", "Donec."};
        OCMain.repSetStringArray(root, "lorem_ipsum", lorem_ipsum);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        //OCArray to int array
        assertEquals(OCType.OC_REP_INT_ARRAY, rep.getType());
        assertTrue(rep.getName().equals("fibonacci"));
        assertNotNull(rep.getValue().getArray());
        assertEquals(fib.length, OCMain.ocArrayToIntArray(rep.getValue().getArray()).length);
        assertArrayEquals(fib, OCMain.ocArrayToIntArray(rep.getValue().getArray()));

        rep = rep.getNext();
        assertNotNull(rep);

        //OCArray to boolean array
        assertEquals(OCType.OC_REP_BOOL_ARRAY, rep.getType());
        assertTrue(rep.getName().equals("flips"));
        assertNotNull(rep.getValue().getArray());
        assertEquals(barray.length, OCMain.ocArrayToBooleanArray(rep.getValue().getArray()).length);
        assertArrayEquals(barray, OCMain.ocArrayToBooleanArray(rep.getValue().getArray()));

        rep = rep.getNext();
        assertNotNull(rep);

        //OCArray to double array
        assertEquals(OCType.OC_REP_DOUBLE_ARRAY, rep.getType());
        assertTrue(rep.getName().equals("math_constants"));
        assertNotNull(rep.getValue().getArray());
        assertEquals(mathConstants.length, OCMain.ocArrayToDoubleArray(rep.getValue().getArray()).length);
        assertArrayEquals(mathConstants, OCMain.ocArrayToDoubleArray(rep.getValue().getArray()), 0.0000001);
        OCMain.repDeleteBuffer();

        rep = rep.getNext();
        assertNotNull(rep);

        //OCArray to string array
        assertEquals(OCType.OC_REP_STRING_ARRAY, rep.getType());
        assertTrue(rep.getName().equals("lorem_ipsum"));
        assertNotNull(rep.getValue().getArray());
        assertEquals(lorem_ipsum.length, OCMain.ocArrayToStringArray(rep.getValue().getArray()).length);
        assertArrayEquals(lorem_ipsum, OCMain.ocArrayToStringArray(rep.getValue().getArray()));

        // TODO solve how to pass arrays of bytes.
        // Note Object arrays not covered by the OCArray type
        OCMain.repDeleteBuffer();
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
        Long a = OCMain.repGetInt(v.getObject(), "a");
        assertNotNull(a);
        assertEquals(1, a.longValue());
        Boolean b = OCMain.repGetBoolean(v.getObject(), "b");
        assertNotNull(b);
        assertEquals(false, b.booleanValue());
        String c = OCMain.repGetString(v.getObject(), "c");
        assertNotNull(c);
        assertTrue(c.equals("three"));
        OCMain.repDeleteBuffer();
    }

    @Test
    public void testValueObjectArray() {
        OCMain.repNewBuffer(1024);
        /*
         * NOTE Object Array is a misnomer when represented in json/cbor it
         * is an array of objects. It is represented in code as a
         * linked list of OCRepresentation objects. When used in code
         * it has the same limitations as a singly-linked-list
         */
        /* 
         * The first part of this test is copy/paste from later test
         * testRepObjectArray (see below) this is the easiest way to
         * to build an object array to place into the OCValue
         */

        /*
         * {
         *   "space_2001": [
         *     {"name": "Dave Bowman", "job": "astronaut"},
         *     {"name": "Frank Poole", "job": "astronaut"},
         *     {"name": "Hal 9000", "job": "AI computer"}
         *   ]
         */
        /* add values to root object */
        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        CborEncoder space2001 = OCMain.repOpenArray(root, "space_2001");
        assertEquals(0, OCMain.repGetCborErrno());

        CborEncoder arrayItemObject;

        arrayItemObject = OCMain.repObjectArrayBeginItem(space2001);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(arrayItemObject, "name", "Dave Bowman");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(arrayItemObject, "job", "astronaut");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repObjectArrayEndItem(space2001, arrayItemObject);
        assertEquals(0, OCMain.repGetCborErrno());

        arrayItemObject = OCMain.repObjectArrayBeginItem(space2001);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(arrayItemObject, "name", "Frank Poole");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(arrayItemObject, "job", "astronaut");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repObjectArrayEndItem(space2001, arrayItemObject);
        assertEquals(0, OCMain.repGetCborErrno());

        arrayItemObject = OCMain.repObjectArrayBeginItem(space2001);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(arrayItemObject, "name", "Hal 9000");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(arrayItemObject, "job", "AI computer");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repObjectArrayEndItem(space2001, arrayItemObject);
        assertEquals(0, OCMain.repGetCborErrno());

        OCMain.repCloseArray(root, space2001);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);
        System.out.println(rep.getType());
        System.out.println(rep.getName());
        OCRepresentation space2001Out = OCMain.repGetObjectArray(rep, "space_2001");
        assertNotNull(space2001Out);

        OCValue v = new OCValue();
        assertNotNull(v);
        v.setObjectArray(space2001Out);

        assertNull(v.getObjectArray().getName());
        assertEquals(OCType.OC_REP_OBJECT, v.getObjectArray().getType());

        OCRepresentation arrayObject;
        /* 1st object item in the array */
        arrayObject = v.getObjectArray().getValue().getObject();
        assertNotNull(arrayObject);
        assertEquals(OCType.OC_REP_STRING, arrayObject.getType());
        assertTrue(arrayObject.getName().equals("name"));
        assertTrue(arrayObject.getValue().getString().equals("Dave Bowman"));
        arrayObject = arrayObject.getNext();
        assertNotNull(arrayObject);
        assertEquals(OCType.OC_REP_STRING, arrayObject.getType());
        assertTrue(arrayObject.getName().equals("job"));
        assertTrue(arrayObject.getValue().getString().equals("astronaut"));
        assertNull(arrayObject.getNext());

        /* 2nd object item in the array */
        assertNotNull(v.getObjectArray().getNext());
        assertEquals(OCType.OC_REP_OBJECT, v.getObjectArray().getNext().getType());
        arrayObject = v.getObjectArray().getNext().getValue().getObject();
        assertNotNull(arrayObject);
        assertEquals(OCType.OC_REP_STRING, arrayObject.getType());
        assertTrue(arrayObject.getName().equals("name"));
        assertTrue(arrayObject.getValue().getString().equals("Frank Poole"));
        arrayObject = arrayObject.getNext();
        assertNotNull(arrayObject);
        assertEquals(OCType.OC_REP_STRING, arrayObject.getType());
        assertTrue(arrayObject.getName().equals("job"));
        assertTrue(arrayObject.getValue().getString().equals("astronaut"));
        assertNull(arrayObject.getNext());

        /* 3rd object item in the array */
        assertNotNull(v.getObjectArray().getNext().getNext());
        assertEquals(OCType.OC_REP_OBJECT, v.getObjectArray().getNext().getNext().getType());
        arrayObject = v.getObjectArray().getNext().getNext().getValue().getObject();
        assertNotNull(arrayObject);
        assertEquals(OCType.OC_REP_STRING, arrayObject.getType());
        assertTrue(arrayObject.getName().equals("name"));
        assertTrue(arrayObject.getValue().getString().equals("Hal 9000"));
        arrayObject = arrayObject.getNext();
        assertNotNull(arrayObject);
        assertEquals(OCType.OC_REP_STRING, arrayObject.getType());
        assertTrue(arrayObject.getName().equals("job"));
        assertTrue(arrayObject.getValue().getString().equals("AI computer"));
        assertNull(arrayObject.getNext());

        /* 4th object item in the array */
        assertNull(v.getObjectArray().getNext().getNext().getNext());
        OCMain.repDeleteBuffer();
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

        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        Long outValue = OCMain.repGetInt(rep, "ultimat_answer");
        assertNotNull(outValue);
        assertEquals(42, outValue.longValue());
        outValue = OCMain.repGetInt(rep, "not_a_key");
        assertNull(outValue);
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

        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        Boolean outValue = OCMain.repGetBoolean(rep, "true_flag");
        assertNotNull(outValue);
        assertEquals(true, outValue.booleanValue());
        outValue = OCMain.repGetBoolean(rep, "not_a_key");
        assertNull(outValue);
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

        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        Double outValue = OCMain.repGetDouble(rep, "pi");
        assertNotNull(outValue);
        assertEquals(3.14, outValue.doubleValue(), 0.001);
        outValue = OCMain.repGetDouble(rep, "not_a_key");
        assertNull(outValue);
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

        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        String outValue = OCMain.repGetString(rep, "hello");
        assertNotNull(outValue);
        assertTrue(outValue.equals("world"));
        outValue = OCMain.repGetString(rep, "empty");
        assertNotNull(outValue);
        assertTrue(outValue.equals(""));
        outValue = OCMain.repGetString(rep, "not_a_key");
        assertNull(outValue);
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
        long fib[] = {1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89};
        OCMain.repSetIntArray(root, "fibonacci", fib);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        long outValue[] = OCMain.repGetIntArray(rep, "fibonacci");
        assertNotNull(outValue);
        assertEquals(fib.length, outValue.length);
        assertArrayEquals(fib, outValue);
        OCMain.repDeleteBuffer();
    }
    
    @Test
    public void testRepByteStringArray() {
        OCMain.repNewBuffer(1024);

        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        assertNotNull(root);
        /* jagged arrays for testing */
        byte ba0[] = {0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        byte ba1[] = {0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x13, 0x21, 0x34, 0x55, (byte)0x89};
        byte ba2[] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                         0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
        byte ba3[] = {0x00, 0x00, (byte)0xff, 0x00, 0x00};
        CborEncoder barray = OCMain.repOpenArray(root, "barray");
        assertEquals(0, OCMain.repGetCborErrno());
        assertNotNull(barray);
        OCMain.repAddByteString(barray, ba0);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repAddByteString(barray, ba1);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repAddByteString(barray, ba2);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repAddByteString(barray, ba3);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repCloseArray(root, barray);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        byte outValue[][] = OCMain.repGetByteStringArray(rep, "barray");
        assertNotNull(outValue);
        assertEquals(4, outValue.length);
        assertEquals(ba0.length, outValue[0].length);
        assertArrayEquals(ba0, outValue[0]);
        assertEquals(ba1.length, outValue[1].length);
        assertArrayEquals(ba1, outValue[1]);
        assertEquals(ba2.length, outValue[2].length);
        assertArrayEquals(ba2, outValue[2]);
        assertEquals(ba3.length, outValue[3].length);
        assertArrayEquals(ba3, outValue[3]);
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
        CborEncoder myObject = OCMain.repOpenObject(root, "my_object");
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

        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);

        OCRepresentation myObjectOut = OCMain.repGetObject(rep, "my_object");
        assertNotNull(myObjectOut);

        Long a = OCMain.repGetInt(myObjectOut, "a");
        assertNotNull(a);
        assertEquals(1, a.longValue());
        Boolean b = OCMain.repGetBoolean(myObjectOut, "b");
        assertNotNull(b);
        assertEquals(false, b.booleanValue());
        String c = OCMain.repGetString(myObjectOut, "c");
        assertNotNull(c);
        assertTrue(c.equals("three"));

        OCMain.repDeleteBuffer();
    }

    @Test
    public void testRepObjectArray() {
        OCMain.repNewBuffer(1024);
        /*
         * NOTE Object Array is a misnomer when represented in json/cbor it
         * is an array of objects. It is represented in code as a
         * linked list of OCRepresentation objects. When used in code
         * it has the same limitations as a singly-linked-list
         */
        /*
         * {
         *   "space_2001": [
         *     {"name": "Dave Bowman", "job": "astronaut"},
         *     {"name": "Frank Poole", "job": "astronaut"},
         *     {"name": "Hal 9000", "job": "AI computer"}
         *   ]
         */
        /* add values to root object */
        CborEncoder root = OCMain.repBeginRootObject();
        assertEquals(0, OCMain.repGetCborErrno());
        CborEncoder space2001 = OCMain.repOpenArray(root, "space_2001");
        assertEquals(0, OCMain.repGetCborErrno());

        CborEncoder arrayItemObject;

        arrayItemObject = OCMain.repObjectArrayBeginItem(space2001);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(arrayItemObject, "name", "Dave Bowman");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(arrayItemObject, "job", "astronaut");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repObjectArrayEndItem(space2001, arrayItemObject);
        assertEquals(0, OCMain.repGetCborErrno());

        arrayItemObject = OCMain.repObjectArrayBeginItem(space2001);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(arrayItemObject, "name", "Frank Poole");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(arrayItemObject, "job", "astronaut");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repObjectArrayEndItem(space2001, arrayItemObject);
        assertEquals(0, OCMain.repGetCborErrno());

        arrayItemObject = OCMain.repObjectArrayBeginItem(space2001);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(arrayItemObject, "name", "Hal 9000");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repSetTextString(arrayItemObject, "job", "AI computer");
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repObjectArrayEndItem(space2001, arrayItemObject);
        assertEquals(0, OCMain.repGetCborErrno());

        OCMain.repCloseArray(root, space2001);
        assertEquals(0, OCMain.repGetCborErrno());
        OCMain.repEndRootObject();
        assertEquals(0, OCMain.repGetCborErrno());

        OCRepresentation rep = OCMain.repGetOCRepresentaionFromRootObject();
        assertNotNull(rep);
        System.out.println(rep.getType());
        System.out.println(rep.getName());
        OCRepresentation space2001Out = OCMain.repGetObjectArray(rep, "space_2001");
        assertNotNull(space2001Out);

        String nameOut;
        String jobOut;

        assertEquals(OCType.OC_REP_OBJECT, space2001Out.getType());
        nameOut = OCMain.repGetString(space2001Out.getValue().getObject(), "name");
        assertNotNull(nameOut);
        assertTrue(nameOut.equals("Dave Bowman"));
        jobOut = OCMain.repGetString(space2001Out.getValue().getObject(), "job");
        assertNotNull(jobOut);
        assertTrue(jobOut.equals("astronaut"));

        space2001Out = space2001Out.getNext();
        assertNotNull(space2001Out);

        assertEquals(OCType.OC_REP_OBJECT, space2001Out.getType());
        nameOut = OCMain.repGetString(space2001Out.getValue().getObject(), "name");
        assertNotNull(nameOut);
        assertTrue(nameOut.equals("Frank Poole"));
        jobOut = OCMain.repGetString(space2001Out.getValue().getObject(), "job");
        assertNotNull(jobOut);
        assertTrue(jobOut.equals("astronaut"));

        space2001Out = space2001Out.getNext();
        assertNotNull(space2001Out);

        assertEquals(OCType.OC_REP_OBJECT, space2001Out.getType());
        nameOut = OCMain.repGetString(space2001Out.getValue().getObject(), "name");
        assertNotNull(nameOut);
        assertTrue(nameOut.equals("Hal 9000"));
        jobOut = OCMain.repGetString(space2001Out.getValue().getObject(), "job");
        assertNotNull(jobOut);
        assertTrue(jobOut.equals("AI computer"));

        OCMain.repDeleteBuffer();
    }
}

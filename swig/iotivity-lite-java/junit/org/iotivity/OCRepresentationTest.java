package org.iotivity;

import static org.junit.Assert.*;

import org.iotivity.OCRepresentation.*;
import org.junit.Test;

public class OCRepresentationTest {
    @Test
    public void testType() {
        OCRepresentation rep = new OCRepresentation();
        assertNotNull(rep);
        rep.setType(OCType.OC_REP_INT);
        assertEquals(OCType.OC_REP_INT, rep.getType());
        assertEquals("{0}", OCRep.toJSON(rep, false));
        assertEquals("{\n  0\n}\n", OCRep.toJSON(rep, true));
    }

    @Test
    public void testNext() {
        OCRepresentation rep1 = new OCRepresentation();
        OCRepresentation rep2 = new OCRepresentation();
        OCRepresentation rep3 = new OCRepresentation();
        assertNotNull(rep1);
        assertNotNull(rep2);
        assertNotNull(rep3);
        rep1.setName("one");
        rep2.setName("two");
        rep3.setName("three");
        rep1.setNext(rep2);
        rep1.getNext().setNext(rep3);
        OCRepresentation r = rep1;
        assertEquals("one", r.getName());
        r = r.getNext();
        assertNotNull(r);
        assertEquals("two", r.getName());
        r = r.getNext();
        assertNotNull(r);
        assertEquals("three", r.getName());
        r = r.getNext();
        assertNull(r);
        assertEquals("{\"one\":null,\"two\":null,\"three\":null}", OCRep.toJSON(rep1, false));
        assertEquals("{\n" +
                     "  \"one\" : null,\n" +
                     "  \"two\" : null,\n" +
                     "  \"three\" : null\n" +
                     "}\n", OCRep.toJSON(rep1, true));
}

    @Test
    public void testName() {
        OCRepresentation rep = new OCRepresentation();
        assertNotNull(rep);
        rep.setName("Sam");
        assertEquals("Sam", rep.getName());
        assertEquals("{\"Sam\":null}", OCRep.toJSON(rep, false));
        assertEquals("{\n  \"Sam\" : null\n}\n", OCRep.toJSON(rep, true));
    }

    @Test
    public void testValue() {
        OCRepresentation rep = new OCRepresentation();
        assertNotNull(rep);
        OCValue v = new OCValue();
        v.setString("happy dog");
        rep.setValue(v);
        assertEquals("happy dog", rep.getValue().getString());
        assertEquals("{null}", OCRep.toJSON(rep, false));
        assertEquals("{\n  null\n}\n", OCRep.toJSON(rep, true));
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
        OCRep.newBuffer(1024);

        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        assertNotNull(root);
        long fib[] = {1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89};
        OCRep.setLongArray(root, "fibonacci", fib);
        assertEquals(0, OCRep.getCborErrno());
        boolean barray[] = {false, false, true, false, false};
        OCRep.setBooleanArray(root, "flips", barray);
        assertEquals(0, OCRep.getCborErrno());
        double mathConstants[] = {3.1415926535, 2.71828,  1.4142135, 1.618033};
        OCRep.setDoubleArray(root, "math_constants", mathConstants);
        assertEquals(0, OCRep.getCborErrno());
        String lorem_ipsum[] = {"Lorem", "ipsum", "dolor", "sit", "amet",
                "consectetur", "adipiscing", "elit.", "Sed",
                "nec", "feugiat", "odio.", "Donec."};
        OCRep.setStringArray(root, "lorem_ipsum", lorem_ipsum);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        //OCArray to int array
        assertEquals(OCType.OC_REP_INT_ARRAY, rep.getType());
        assertTrue(rep.getName().equals("fibonacci"));
        assertNotNull(rep.getValue().getArray());
        assertEquals(fib.length, OCRep.ocArrayToLongArray(rep.getValue().getArray()).length);
        assertArrayEquals(fib, OCRep.ocArrayToLongArray(rep.getValue().getArray()));

        rep = rep.getNext();
        assertNotNull(rep);

        assertEquals("{\"flips\":[false,false,true,false,false],"
                + "\"math_constants\":[3.141593,2.718280,1.414214,1.618033],"
                + "\"lorem_ipsum\":[\"Lorem\",\"ipsum\",\"dolor\",\"sit\",\"amet\",\"consectetur\",\"adipiscing\""
                + ",\"elit.\",\"Sed\",\"nec\",\"feugiat\",\"odio.\",\"Donec.\"]}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"flips\" : [false, false, true, false, false],\n"
                + "  \"math_constants\" : [3.141593, 2.718280, 1.414214, 1.618033],\n"
                + "  \"lorem_ipsum\" : [\n"
                + "    \"Lorem\",\n"
                + "    \"ipsum\",\n"
                + "    \"dolor\",\n"
                + "    \"sit\",\n"
                + "    \"amet\",\n"
                + "    \"consectetur\",\n"
                + "    \"adipiscing\",\n"
                + "    \"elit.\",\n"
                + "    \"Sed\",\n"
                + "    \"nec\",\n"
                + "    \"feugiat\",\n"
                + "    \"odio.\",\n"
                + "    \"Donec.\"\n"
                + "  ]\n"
                + "}\n", OCRep.toJSON(rep, true));

        //OCArray to boolean array
        assertEquals(OCType.OC_REP_BOOL_ARRAY, rep.getType());
        assertTrue(rep.getName().equals("flips"));
        assertNotNull(rep.getValue().getArray());
        assertEquals(barray.length, OCRep.ocArrayToBooleanArray(rep.getValue().getArray()).length);
        assertArrayEquals(barray, OCRep.ocArrayToBooleanArray(rep.getValue().getArray()));

        rep = rep.getNext();
        assertNotNull(rep);

        //OCArray to double array
        assertEquals(OCType.OC_REP_DOUBLE_ARRAY, rep.getType());
        assertTrue(rep.getName().equals("math_constants"));
        assertNotNull(rep.getValue().getArray());
        assertEquals(mathConstants.length, OCRep.ocArrayToDoubleArray(rep.getValue().getArray()).length);
        assertArrayEquals(mathConstants, OCRep.ocArrayToDoubleArray(rep.getValue().getArray()), 0.0000001);
        OCRep.deleteBuffer();

        rep = rep.getNext();
        assertNotNull(rep);

        //OCArray to string array
        assertEquals(OCType.OC_REP_STRING_ARRAY, rep.getType());
        assertTrue(rep.getName().equals("lorem_ipsum"));
        assertNotNull(rep.getValue().getArray());
        assertEquals(lorem_ipsum.length, OCRep.ocArrayToStringArray(rep.getValue().getArray()).length);
        assertArrayEquals(lorem_ipsum, OCRep.ocArrayToStringArray(rep.getValue().getArray()));

        // TODO solve how to pass arrays of bytes.
        // Note Object arrays not covered by the OCArray type
        OCRep.deleteBuffer();
    }

    @Test
    public void testValueObject() {
        OCRep.newBuffer(1024);

        /*
         * Create an OCRepresentation with the following
         *  {
         *     "a": 1,
         *     "b": false,
         *     "c": "three"
         *   }
         */
        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setLong(root, "a", 1);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setBoolean(root, "b", false);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(root, "c", "three");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        assertEquals("{\"a\":1,\"b\":false,\"c\":\"three\"}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"a\" : 1,\n"
                + "  \"b\" : false,\n"
                + "  \"c\" : \"three\"\n"
                + "}\n", OCRep.toJSON(rep, true));

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
        Long a = OCRep.getLong(v.getObject(), "a");
        assertNotNull(a);
        assertEquals(1, a.longValue());
        Boolean b = OCRep.getBoolean(v.getObject(), "b");
        assertNotNull(b);
        assertEquals(false, b.booleanValue());
        String c = OCRep.getString(v.getObject(), "c");
        assertNotNull(c);
        assertTrue(c.equals("three"));
        OCRep.deleteBuffer();
    }

    @Test
    public void testValueObjectArray() {
        OCRep.newBuffer(1024);
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
        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        CborEncoder space2001 = OCRep.openArray(root, "space_2001");
        assertEquals(0, OCRep.getCborErrno());

        CborEncoder arrayItemObject;

        arrayItemObject = OCRep.objectArrayBeginItem(space2001);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(arrayItemObject, "name", "Dave Bowman");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(arrayItemObject, "job", "astronaut");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.objectArrayEndItem(space2001, arrayItemObject);
        assertEquals(0, OCRep.getCborErrno());

        arrayItemObject = OCRep.objectArrayBeginItem(space2001);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(arrayItemObject, "name", "Frank Poole");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(arrayItemObject, "job", "astronaut");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.objectArrayEndItem(space2001, arrayItemObject);
        assertEquals(0, OCRep.getCborErrno());

        arrayItemObject = OCRep.objectArrayBeginItem(space2001);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(arrayItemObject, "name", "Hal 9000");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(arrayItemObject, "job", "AI computer");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.objectArrayEndItem(space2001, arrayItemObject);
        assertEquals(0, OCRep.getCborErrno());

        OCRep.closeArray(root, space2001);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        assertEquals("{\"space_2001\":[{\"name\":\"Dave Bowman\",\"job\":\"astronaut\"},"
                + "{\"name\":\"Frank Poole\",\"job\":\"astronaut\"},"
                + "{\"name\":\"Hal 9000\",\"job\":\"AI computer\"}]}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"space_2001\" : [\n"
                + "    {\n"
                + "      \"name\" : \"Dave Bowman\",\n"
                + "      \"job\" : \"astronaut\"\n"
                + "    },\n"
                + "    {\n"
                + "      \"name\" : \"Frank Poole\",\n"
                + "      \"job\" : \"astronaut\"\n"
                + "    },\n"
                + "    {\n"
                + "      \"name\" : \"Hal 9000\",\n"
                + "      \"job\" : \"AI computer\"\n"
                + "    }]\n"
                + "}\n", OCRep.toJSON(rep, true));

        assertEquals(OCType.OC_REP_OBJECT_ARRAY, rep.getType());
        assertEquals("space_2001", rep.getName());
        OCRepresentation space2001Out = OCRep.getObjectArray(rep, "space_2001");
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
        OCRep.deleteBuffer();
    }

    @Test
    public void testRepInt() {
        OCRep.newBuffer(1024);

        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        assertNotNull(root);
        OCRep.setLong(root, "ultimat_answer", 42);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        assertEquals("{\"ultimat_answer\":42}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"ultimat_answer\" : 42\n"
                + "}\n", OCRep.toJSON(rep, true));

        Long outValue = OCRep.getLong(rep, "ultimat_answer");
        assertNotNull(outValue);
        assertEquals(42, outValue.longValue());
        outValue = OCRep.getLong(rep, "not_a_key");
        assertNull(outValue);
        OCRep.deleteBuffer();
    }

    @Test
    public void testRepBoolean() {
        OCRep.newBuffer(1024);

        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        assertNotNull(root);
        OCRep.setBoolean(root, "true_flag", true);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        assertEquals("{\"true_flag\":true}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"true_flag\" : true\n"
                + "}\n", OCRep.toJSON(rep, true));

        Boolean outValue = OCRep.getBoolean(rep, "true_flag");
        assertNotNull(outValue);
        assertEquals(true, outValue.booleanValue());
        outValue = OCRep.getBoolean(rep, "not_a_key");
        assertNull(outValue);
        OCRep.deleteBuffer();
    }

    @Test
    public void testRepDouble() {
        OCRep.newBuffer(1024);
        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        assertNotNull(root);
        OCRep.setDouble(root, "pi", 3.14);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        assertEquals("{\"pi\":3.140000}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"pi\" : 3.140000\n"
                + "}\n", OCRep.toJSON(rep, true));

        Double outValue = OCRep.getDouble(rep, "pi");
        assertNotNull(outValue);
        assertEquals(3.14, outValue.doubleValue(), 0.001);
        outValue = OCRep.getDouble(rep, "not_a_key");
        assertNull(outValue);
        OCRep.deleteBuffer();
    }

    @Test
    public void testRepString() {
        OCRep.newBuffer(1024);

        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        assertNotNull(root);
        OCRep.setTextString(root, "hello", "world");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(root, "empty", "");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        assertEquals("{\"hello\":\"world\",\"empty\":\"\"}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"hello\" : \"world\",\n"
                + "  \"empty\" : \"\"\n"
                + "}\n", OCRep.toJSON(rep, true));

        String outValue = OCRep.getString(rep, "hello");
        assertNotNull(outValue);
        assertTrue(outValue.equals("world"));
        outValue = OCRep.getString(rep, "empty");
        assertNotNull(outValue);
        assertTrue(outValue.equals(""));
        outValue = OCRep.getString(rep, "not_a_key");
        assertNull(outValue);
        OCRep.deleteBuffer();
    }

    @Test
    public void testRepBooleanArray() {
        OCRep.newBuffer(1024);

        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        assertNotNull(root);
        boolean barray[] = {false, false, true, false, false};
        OCRep.setBooleanArray(root, "flips", barray);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        assertEquals("{\"flips\":[false,false,true,false,false]}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"flips\" : [false, false, true, false, false]\n"
                + "}\n", OCRep.toJSON(rep, true));

        boolean outValue[] = OCRep.getBooleanArray(rep, "flips");
        assertNotNull(outValue);
        assertEquals(barray.length, outValue.length);
        assertArrayEquals(barray, outValue);
        OCRep.deleteBuffer();
    }

    @Test
    public void testRepDoubleArray() {
        OCRep.newBuffer(1024);

        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        assertNotNull(root);
        double mathConstants[] = {3.1415926535, 2.71828,  1.4142135, 1.618033};
        OCRep.setDoubleArray(root, "math_constants", mathConstants);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        assertEquals("{\"math_constants\":[3.141593,2.718280,1.414214,1.618033]}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"math_constants\" : [3.141593, 2.718280, 1.414214, 1.618033]\n"
                + "}\n", OCRep.toJSON(rep, true));
        
        double outValue[] = OCRep.getDoubleArray(rep, "math_constants");
        assertNotNull(outValue);
        assertEquals(mathConstants.length, outValue.length);
        assertArrayEquals(mathConstants, outValue, 0.000001);
        OCRep.deleteBuffer();
    }

    @Test
    public void testRepIntArray() {
        OCRep.newBuffer(1024);

        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        assertNotNull(root);
        long fib[] = {1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89};
        OCRep.setLongArray(root, "fibonacci", fib);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        assertEquals("{\"fibonacci\":[1,1,2,3,5,8,13,21,34,55,89]}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"fibonacci\" : [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89]\n"
                + "}\n", OCRep.toJSON(rep, true));

        long outValue[] = OCRep.getLongArray(rep, "fibonacci");
        assertNotNull(outValue);
        assertEquals(fib.length, outValue.length);
        assertArrayEquals(fib, outValue);
        OCRep.deleteBuffer();
    }
    
    @Test
    public void testRepByteStringArray() {
        OCRep.newBuffer(1024);

        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        assertNotNull(root);
        /* jagged arrays for testing */
        byte ba0[] = {0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        byte ba1[] = {0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x13, 0x21, 0x34, 0x55, (byte)0x89};
        byte ba2[] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                         0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
        byte ba3[] = {0x00, 0x00, (byte)0xff, 0x00, 0x00};
        CborEncoder barray = OCRep.openArray(root, "barray");
        assertEquals(0, OCRep.getCborErrno());
        assertNotNull(barray);
        OCRep.addByteString(barray, ba0);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.addByteString(barray, ba1);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.addByteString(barray, ba2);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.addByteString(barray, ba3);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.closeArray(root, barray);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        // note: toJSON defaults to base64 encoding for all byte-arrays
        assertEquals("{\"barray\":[\"AQECAwQFBg==\",\"AQECAwUIEyE0VYk=\","
                + "\"QkJCQkJCQkJCQkJCQkJCQkJCQkI=\",\"AAD/AAA=\"]}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"barray\" : [\n"
                + "    \"AQECAwQFBg==\",\n"
                + "    \"AQECAwUIEyE0VYk=\",\n"
                + "    \"QkJCQkJCQkJCQkJCQkJCQkJCQkI=\",\n"
                + "    \"AAD/AAA=\"\n"
                + "  ]\n"
                + "}\n", OCRep.toJSON(rep, true));

        byte outValue[][] = OCRep.getByteStringArray(rep, "barray");
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
        OCRep.deleteBuffer();
    }

    @Test
    public void testRepStringArray() {
        OCRep.newBuffer(1024);

        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        assertNotNull(root);
        String lorem_ipsum[] = {"Lorem", "ipsum", "dolor", "sit", "amet",
                                "consectetur", "adipiscing", "elit.", "Sed",
                                "nec", "feugiat", "odio.", "Donec."};
        OCRep.setStringArray(root, "lorem_ipsum", lorem_ipsum);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        assertEquals("{\"lorem_ipsum\":[\"Lorem\",\"ipsum\",\"dolor\",\"sit\",\"amet\",\"consectetur\",\"adipiscing\","
                + "\"elit.\",\"Sed\",\"nec\",\"feugiat\",\"odio.\",\"Donec.\"]}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"lorem_ipsum\" : [\n"
                + "    \"Lorem\",\n"
                + "    \"ipsum\",\n"
                + "    \"dolor\",\n"
                + "    \"sit\",\n"
                + "    \"amet\",\n"
                + "    \"consectetur\",\n"
                + "    \"adipiscing\",\n"
                + "    \"elit.\",\n"
                + "    \"Sed\",\n"
                + "    \"nec\",\n"
                + "    \"feugiat\",\n"
                + "    \"odio.\",\n"
                + "    \"Donec.\"\n"
                + "  ]\n"
                + "}\n", OCRep.toJSON(rep, true));

        String outValue[] = OCRep.getStringArray(rep, "lorem_ipsum");
        assertNotNull(outValue);
        assertEquals(lorem_ipsum.length, outValue.length);
        assertArrayEquals(lorem_ipsum, outValue);
        OCRep.deleteBuffer();
    }

    @Test
    public void testRepByteString() {
        OCRep.newBuffer(1024);

        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        assertNotNull(root);
        byte fibBytes[] = {0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x13, 0x21, 0x34, 0x55, (byte)0x89};
        OCRep.setByteString(root, "fib_bytes", fibBytes);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        // note toJSON uses base64 encoding for all byte arrays.
        assertEquals("{\"fib_bytes\":\"AQECAwUIEyE0VYk=\"}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"fib_bytes\" : \"AQECAwUIEyE0VYk=\"\n"
                + "}\n", OCRep.toJSON(rep, true));

        byte outValue[] = OCRep.getByteString(rep, "fib_bytes");
        assertNotNull(outValue);
        assertEquals(fibBytes.length, outValue.length);
        assertArrayEquals(fibBytes, outValue);
        OCRep.deleteBuffer();
    }

    @Test
    public void testRepObject() {
        OCRep.newBuffer(1024);

        /*
         * {
         *   "my_object": {
         *     "a": 1,
         *     "b": false,
         *     "c": "three"
         *   }
         * }
         */
        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        CborEncoder myObject = OCRep.openObject(root, "my_object");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setLong(myObject, "a", 1);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setBoolean(myObject, "b", false);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(myObject, "c", "three");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.closeObject(root, myObject);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        assertEquals("{\"my_object\":{\"a\":1,\"b\":false,\"c\":\"three\"}}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"my_object\" : {\n"
                + "    \"a\" : 1,\n"
                + "    \"b\" : false,\n"
                + "    \"c\" : \"three\"\n"
                + "  }\n"
                + "}\n", OCRep.toJSON(rep, true));

        OCRepresentation myObjectOut = OCRep.getObject(rep, "my_object");
        assertNotNull(myObjectOut);

        Long a = OCRep.getLong(myObjectOut, "a");
        assertNotNull(a);
        assertEquals(1, a.longValue());
        Boolean b = OCRep.getBoolean(myObjectOut, "b");
        assertNotNull(b);
        assertEquals(false, b.booleanValue());
        String c = OCRep.getString(myObjectOut, "c");
        assertNotNull(c);
        assertTrue(c.equals("three"));

        OCRep.deleteBuffer();
    }

    @Test
    public void testRepObjectArray() {
        OCRep.newBuffer(1024);
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
        CborEncoder root = OCRep.beginRootObject();
        assertEquals(0, OCRep.getCborErrno());
        CborEncoder space2001 = OCRep.openArray(root, "space_2001");
        assertEquals(0, OCRep.getCborErrno());

        CborEncoder arrayItemObject;

        arrayItemObject = OCRep.objectArrayBeginItem(space2001);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(arrayItemObject, "name", "Dave Bowman");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(arrayItemObject, "job", "astronaut");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.objectArrayEndItem(space2001, arrayItemObject);
        assertEquals(0, OCRep.getCborErrno());

        arrayItemObject = OCRep.objectArrayBeginItem(space2001);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(arrayItemObject, "name", "Frank Poole");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(arrayItemObject, "job", "astronaut");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.objectArrayEndItem(space2001, arrayItemObject);
        assertEquals(0, OCRep.getCborErrno());

        arrayItemObject = OCRep.objectArrayBeginItem(space2001);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(arrayItemObject, "name", "Hal 9000");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.setTextString(arrayItemObject, "job", "AI computer");
        assertEquals(0, OCRep.getCborErrno());
        OCRep.objectArrayEndItem(space2001, arrayItemObject);
        assertEquals(0, OCRep.getCborErrno());

        OCRep.closeArray(root, space2001);
        assertEquals(0, OCRep.getCborErrno());
        OCRep.endRootObject();
        assertEquals(0, OCRep.getCborErrno());

        OCRepresentation rep = OCRep.getOCRepresentaionFromRootObject();
        assertNotNull(rep);

        assertEquals("{\"space_2001\":[{\"name\":\"Dave Bowman\",\"job\":\"astronaut\"},"
                + "{\"name\":\"Frank Poole\",\"job\":\"astronaut\"},"
                + "{\"name\":\"Hal 9000\",\"job\":\"AI computer\"}]}", OCRep.toJSON(rep, false));
        assertEquals("{\n"
                + "  \"space_2001\" : [\n"
                + "    {\n"
                + "      \"name\" : \"Dave Bowman\",\n"
                + "      \"job\" : \"astronaut\"\n"
                + "    },\n"
                + "    {\n"
                + "      \"name\" : \"Frank Poole\",\n"
                + "      \"job\" : \"astronaut\"\n"
                + "    },\n"
                + "    {\n"
                + "      \"name\" : \"Hal 9000\",\n"
                + "      \"job\" : \"AI computer\"\n"
                + "    }]\n"
                + "}\n", OCRep.toJSON(rep, true));

        OCRepresentation space2001Out = OCRep.getObjectArray(rep, "space_2001");
        assertNotNull(space2001Out);

        String nameOut;
        String jobOut;

        assertEquals(OCType.OC_REP_OBJECT, space2001Out.getType());
        nameOut = OCRep.getString(space2001Out.getValue().getObject(), "name");
        assertNotNull(nameOut);
        assertTrue(nameOut.equals("Dave Bowman"));
        jobOut = OCRep.getString(space2001Out.getValue().getObject(), "job");
        assertNotNull(jobOut);
        assertTrue(jobOut.equals("astronaut"));

        space2001Out = space2001Out.getNext();
        assertNotNull(space2001Out);

        assertEquals(OCType.OC_REP_OBJECT, space2001Out.getType());
        nameOut = OCRep.getString(space2001Out.getValue().getObject(), "name");
        assertNotNull(nameOut);
        assertTrue(nameOut.equals("Frank Poole"));
        jobOut = OCRep.getString(space2001Out.getValue().getObject(), "job");
        assertNotNull(jobOut);
        assertTrue(jobOut.equals("astronaut"));

        space2001Out = space2001Out.getNext();
        assertNotNull(space2001Out);

        assertEquals(OCType.OC_REP_OBJECT, space2001Out.getType());
        nameOut = OCRep.getString(space2001Out.getValue().getObject(), "name");
        assertNotNull(nameOut);
        assertTrue(nameOut.equals("Hal 9000"));
        jobOut = OCRep.getString(space2001Out.getValue().getObject(), "job");
        assertNotNull(jobOut);
        assertTrue(jobOut.equals("AI computer"));

        OCRep.deleteBuffer();
    }
}

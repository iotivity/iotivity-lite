package org.iotivity.oc;

import org.iotivity.*;

public class OcRepresentation {

    private OCRepresentation nativeRepresentation;

    public OCRepresentation getNative() {
        return nativeRepresentation;
    }

    // ctor is private, use factory ctor
    private OcRepresentation(OCRepresentation nativeRep) {
        if (nativeRep == null) {
            throw new IllegalArgumentException("Native OCRepresentation cannot be null");
        }
        nativeRepresentation = nativeRep;
    }

    static public OcRepresentation createOcRepresentaionFromRoot() {
        OCRepresentation nativeRep = OCMain.repGetOCRepresentaionFromRootObject();
        return new OcRepresentation(nativeRep);
    }

    public Boolean getBoolean() {
        return nativeRepresentation.getValue().getBool();
    }

    public Long getLong() {
        return nativeRepresentation.getValue().getInteger();
    }

    public Double getDouble() {
        return nativeRepresentation.getValue().getDouble();
    }

    public String getString() {
        return nativeRepresentation.getValue().getString();
    }

    public OCArray getArray() {
        return nativeRepresentation.getValue().getArray();
    }

    public OcRepresentation getObject() {
        OCRepresentation nativeRep = nativeRepresentation.getValue().getObject();
        return new OcRepresentation(nativeRep);
    }

    public OcRepresentation getObjectArray() {
        OCRepresentation nativeRep = nativeRepresentation.getValue().getObjectArray();
        return new OcRepresentation(nativeRep);
    }

    public OCValue getValue() {
        return nativeRepresentation.getValue();
    }

    public Boolean getBoolean(String key) {
        return OCMain.repGetBoolean(nativeRepresentation, key);
    }

    public Long getLong(String key) {
        return OCMain.repGetLong(nativeRepresentation, key);
    }

    public Double getDouble(String key) {
        return OCMain.repGetDouble(nativeRepresentation, key);
    }

    public String getString(String key) {
        return OCMain.repGetString(nativeRepresentation, key);
    }

    public byte[] getByteString(String key) {
        return OCMain.repGetByteString(nativeRepresentation, key);
    }

    public OcRepresentation getObject(String key) {
        OCRepresentation nativeRep = OCMain.repGetObject(nativeRepresentation, key);
        return new OcRepresentation(nativeRep);
    }

    public boolean[] getBooleanArray(String key) {
        return OCMain.repGetBooleanArray(nativeRepresentation, key);
    }

    public long[] getLongArray(String key) {
        return OCMain.repGetLongArray(nativeRepresentation, key);
    }

    public double[] getDoubleArray(String key) {
        return OCMain.repGetDoubleArray(nativeRepresentation, key);
    }

    public String[] getStringArray(String key) {
        return OCMain.repGetStringArray(nativeRepresentation, key);
    }

    public byte[][] getByteStringArray(String key) {
        return OCMain.repGetByteStringArray(nativeRepresentation, key);
    }

    public OcRepresentation getObjectArray(String key) {
        OCRepresentation nativeRep = OCMain.repGetObjectArray(nativeRepresentation, key);
        return new OcRepresentation(nativeRep);
    }

    public OcRepresentation getNext() {
        OCRepresentation nativeRep = nativeRepresentation.getNext();
        if (nativeRep != null) {
            return new OcRepresentation(nativeRep);
        }
        return null;
    }
}

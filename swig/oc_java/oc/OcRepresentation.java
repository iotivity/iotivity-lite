package org.iotivity.oc;

import org.iotivity.*;

public class OcRepresentation {

    private OCRepresentation nativeRepresentation;

    // ctor is private, use factory ctor
    private OcRepresentation(OCRepresentation nativeRep) {
        if (nativeRep == null) {
            throw new IllegalArgumentException("Native OCRepresentation cannot be null");
        }
        nativeRepresentation = nativeRep;
    }

    static public OcRepresentation createOcRepresentaionFromRoot() {
        OCRepresentation nativeRep = OCRep.getOCRepresentaionFromRootObject();
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
        return OCRep.getBoolean(nativeRepresentation, key);
    }

    public Long getLong(String key) {
        return OCRep.getLong(nativeRepresentation, key);
    }

    public Double getDouble(String key) {
        return OCRep.getDouble(nativeRepresentation, key);
    }

    public String getString(String key) {
        return OCRep.getString(nativeRepresentation, key);
    }

    public byte[] getByteString(String key) {
        return OCRep.getByteString(nativeRepresentation, key);
    }

    public OcRepresentation getObject(String key) {
        OCRepresentation nativeRep = OCRep.getObject(nativeRepresentation, key);
        return new OcRepresentation(nativeRep);
    }

    public boolean[] getBooleanArray(String key) {
        return OCRep.getBooleanArray(nativeRepresentation, key);
    }

    public long[] getLongArray(String key) {
        return OCRep.getLongArray(nativeRepresentation, key);
    }

    public double[] getDoubleArray(String key) {
        return OCRep.getDoubleArray(nativeRepresentation, key);
    }

    public String[] getStringArray(String key) {
        return OCRep.getStringArray(nativeRepresentation, key);
    }

    public byte[][] getByteStringArray(String key) {
        return OCRep.getByteStringArray(nativeRepresentation, key);
    }

    public OcRepresentation getObjectArray(String key) {
        OCRepresentation nativeRep = OCRep.getObjectArray(nativeRepresentation, key);
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

package org.iotivity.oc;

import org.iotivity.*;

/**
 * OcRepresentation provides access to extract values from a CBOR representation.
 * <p>
 * An OcRepresenation is typically constructed from the payload of an OCClientResponse in the handler() method of an OCResponseHandler.
 *
 * @see OCResponseHandler#handler
 * @see OCClientResponse#getPayload
 */
public class OcRepresentation {

    private OCRepresentation nativeRepresentation;

    public OcRepresentation(OCRepresentation nativeRep) {
        if (nativeRep == null) {
            throw new IllegalArgumentException("Native OCRepresentation cannot be null");
        }
        nativeRepresentation = nativeRep;
    }

    // for unit testing only
    static public OcRepresentation createOcRepresentaionFromRoot() throws OcCborException {
        OCRepresentation nativeRep = OCRep.getOCRepresentaionFromRootObject();
        if (nativeRep != null) {
            return new OcRepresentation(nativeRep);
        }
        throw new OcCborException("Failed to create OcRepresentation from root object");
    }

    public String getKey() {
        return nativeRepresentation.getName();
    }

    public OCType getType() {
        return nativeRepresentation.getType();
    }

    public boolean getBoolean() throws OcCborException {
        Boolean returnValue = getValue().getBool();
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get boolean");
    }

    public long getLong() throws OcCborException {
        Long returnValue = getValue().getInteger();
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get long");
    }

    public double getDouble() throws OcCborException {
        Double returnValue = getValue().getDouble();
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get double");
    }

    public String getString() throws OcCborException {
        String returnValue = getValue().getString();
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get string");
    }

    public OCArray getArray() throws OcCborException {
        OCArray returnValue = getValue().getArray();
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get array");
    }

    public OcRepresentation getObject() throws OcCborException {
        OCRepresentation nativeRep = getValue().getObject();
        if (nativeRep != null) {
            return new OcRepresentation(nativeRep);
        }
        throw new OcCborException("Failed to get object");
    }

    public OcRepresentation getObjectArray() throws OcCborException {
        OCRepresentation nativeRep = getValue().getObjectArray();
        if (nativeRep != null) {
            return new OcRepresentation(nativeRep);
        }
        throw new OcCborException("Failed to get object array");
    }

    public OCValue getValue() throws OcCborException {
        OCValue returnValue = nativeRepresentation.getValue();
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get value");
    }

    public boolean getBoolean(String key) throws OcCborException {
        Boolean returnValue = OCRep.getBoolean(nativeRepresentation, key);
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get boolean for key " + key);
    }

    public long getLong(String key) throws OcCborException {
        Long returnValue = OCRep.getLong(nativeRepresentation, key);
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get long for key " + key);
    }

    public double getDouble(String key) throws OcCborException {
        Double returnValue = OCRep.getDouble(nativeRepresentation, key);
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get double for key " + key);
    }

    public String getString(String key) throws OcCborException {
        String returnValue = OCRep.getString(nativeRepresentation, key);
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get string for key " + key);
    }

    public byte[] getByteString(String key) throws OcCborException {
        byte[] returnValue = OCRep.getByteString(nativeRepresentation, key);
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get byte string for key " + key);
    }

    public OcRepresentation getObject(String key) throws OcCborException {
        OCRepresentation nativeRep = OCRep.getObject(nativeRepresentation, key);
        if (nativeRep != null) {
            return new OcRepresentation(nativeRep);
        }
        throw new OcCborException("Failed to get object for key " + key);
    }

    public boolean[] getBooleanArray(String key) throws OcCborException {
        boolean[] returnValue = OCRep.getBooleanArray(nativeRepresentation, key);
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get boolean array for key " + key);
    }

    public long[] getLongArray(String key) throws OcCborException {
        long[] returnValue = OCRep.getLongArray(nativeRepresentation, key);
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get long array for key " + key);
    }

    public double[] getDoubleArray(String key) throws OcCborException {
        double[] returnValue = OCRep.getDoubleArray(nativeRepresentation, key);
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get double array for key " + key);
    }

    public String[] getStringArray(String key) throws OcCborException {
        String[] returnValue = OCRep.getStringArray(nativeRepresentation, key);
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get string array for key " + key);
    }

    public byte[][] getByteStringArray(String key) throws OcCborException {
        byte[][] returnValue = OCRep.getByteStringArray(nativeRepresentation, key);
        if (returnValue != null) {
            return returnValue;
        }
        throw new OcCborException("Failed to get byte string array for key " + key);
    }

    public OcRepresentation getObjectArray(String key) throws OcCborException {
        OCRepresentation nativeRep = OCRep.getObjectArray(nativeRepresentation, key);
        if (nativeRep != null) {
            return new OcRepresentation(nativeRep);
        }
        throw new OcCborException("Failed to get object array for key " + key);
    }

    public OcRepresentation getNext() {
        OCRepresentation nativeRep = nativeRepresentation.getNext();
        if (nativeRep != null) {
            return new OcRepresentation(nativeRep);
        }
        return null;
    }
}

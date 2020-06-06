package org.iotivity.oc;

import org.iotivity.*;

/**
 * OcCborEncoder provides methods to encode a CBOR representation.
 * <p>
 * All OcCborEncoder constructors are static.  To close the cbor encoder, use done().
 */
public class OcCborEncoder {

    private boolean isDone;
    private boolean hasKey;
    private EncoderType encoderType;
    private OcCborEncoder parentEncoder;
    private CborEncoder nativeCborEncoder;

    public enum EncoderType {
        ROOT, LINKS_ARRAY, OBJECT, ARRAY, ARRAY_ITEM
    }

    // ctors are private, use a factory ctor
    private OcCborEncoder(EncoderType type, CborEncoder nativeEncoder) {
        this(type, null, false, nativeEncoder);
    }

    private OcCborEncoder(EncoderType type, OcCborEncoder parent, boolean key, CborEncoder nativeEncoder) {
        encoderType = type;
        parentEncoder = parent;
        hasKey = key;
        nativeCborEncoder = nativeEncoder;
    }

    /**
     * Returns a cbor encoder for a root or links array. Must be closed using done().
     *
     * @param type  the EncoderType
     * @return a OcCborEncoder instance
     *
     * @see EncoderType#ROOT
     * @see EncoderType#LINKS_ARRAY
     * @see OcCborEncoder#done
     */
    static public OcCborEncoder createOcCborEncoder(EncoderType type) {
        if (type == null) {
            throw new IllegalArgumentException("EncoderType cannot be null");
        }

        CborEncoder nativeEncoder;

        switch (type) {
        case ROOT:
            nativeEncoder = OCRep.beginRootObject();
            break;
        case LINKS_ARRAY:
            nativeEncoder = OCRep.beginLinksArray();
            break;
        default:
            throw new IllegalArgumentException("Illegal EncoderType " + type.name());
        }

        OcCborEncoder cborEncoder = new OcCborEncoder(type, nativeEncoder);
        return cborEncoder;
    }

    /**
     * Returns a cbor encoder for an un-keyed object, array or array item. Must be closed using done().
     *
     * @param type  the EncoderType
     * @param parent  the enclosing cbor encoder
     * @return a OcCborEncoder instance
     *
     * @see EncoderType#OBJECT
     * @see EncoderType#ARRAY
     * @see EncoderType#ARRAY_ITEM
     * @see OcCborEncoder#done
     */
    static public OcCborEncoder createOcCborEncoder(EncoderType type, OcCborEncoder parent) {
        if (type == null) {
            throw new IllegalArgumentException("EncoderType cannot be null");
        }
        if (parent == null) {
            throw new IllegalArgumentException("OcCborEncoder parent cannot be null");
        }

        CborEncoder nativeEncoder;

        switch (type) {
        case OBJECT:
            nativeEncoder = OCRep.beginObject(parent.getNativeEncoder());
            break;
        case ARRAY:
            nativeEncoder = OCRep.beginArray(parent.getNativeEncoder());
            break;
        case ARRAY_ITEM:
            nativeEncoder = OCRep.objectArrayBeginItem(parent.getNativeEncoder());
            break;
        default:
            throw new IllegalArgumentException("Illegal EncoderType " + type.name());
        }

        OcCborEncoder cborEncoder = new OcCborEncoder(type, parent, false, nativeEncoder);
        return cborEncoder;
    }

    /**
     * Returns a cbor encoder for a keyed object or array. Must be closed using done().
     *
     * @param type  the EncoderType
     * @param parent  the enclosing cbor encoder
     * @param key  the key of this cbor encoder
     * @return a OcCborEncoder instance
     *
     * @see EncoderType#OBJECT
     * @see EncoderType#ARRAY
     * @see OcCborEncoder#done
     */
    static public OcCborEncoder createOcCborEncoder(EncoderType type, OcCborEncoder parent, String key) {
        if (type == null) {
            throw new IllegalArgumentException("EncoderType cannot be null");
        }
        if (parent == null) {
            throw new IllegalArgumentException("OcCborEncoder parent cannot be null");
        }
        if (key == null) {
            throw new IllegalArgumentException("String key cannot be null");
        }

        CborEncoder nativeEncoder;

        switch (type) {
        case OBJECT:
            nativeEncoder = OCRep.openObject(parent.getNativeEncoder(), key);
            break;
        case ARRAY:
            nativeEncoder = OCRep.openArray(parent.getNativeEncoder(), key);
            break;
        default:
            throw new IllegalArgumentException("Illegal EncoderType " + type.name());
        }

        OcCborEncoder cborEncoder = new OcCborEncoder(type, parent, true, nativeEncoder);
        return cborEncoder;
    }

    /**
     * Closes an OcCborEncoder.
     * <p>
     * Must be called to properly close the cbor encoder.
     */
    public void done() {
        if (isDone) {
            throw new UnsupportedOperationException(
                    "done() cannot be called twice. Encoder type is " + encoderType.name());
        }

        switch (encoderType) {
        case ROOT:
            OCRep.endRootObject();
            break;
        case LINKS_ARRAY:
            OCRep.endLinksArray();
            break;
        case OBJECT:
            if (hasKey) {
                OCRep.closeObject(parentEncoder.getNativeEncoder(), getNativeEncoder());
            } else {
                OCRep.endObject(parentEncoder.getNativeEncoder(), getNativeEncoder());
            }
            break;
        case ARRAY:
            if (hasKey) {
                OCRep.closeArray(parentEncoder.getNativeEncoder(), getNativeEncoder());
            } else {
                OCRep.endArray(parentEncoder.getNativeEncoder(), getNativeEncoder());
            }
            break;
        case ARRAY_ITEM:
            OCRep.objectArrayEndItem(parentEncoder.getNativeEncoder(), getNativeEncoder());
            break;
        default:
            break;
        }

        isDone = true;
    }

    public void processBaselineInterface(OcResource resource) {
        processBaselineInterface(resource.getNativeResource());
    }

    public void processBaselineInterface(OCResource resource) {
        if (encoderType != EncoderType.ROOT) {
            throw new UnsupportedOperationException(getBadEncoderTypeMsg(encoderType, EncoderType.ROOT));
        }
        OCMain.processBaselineInterface(resource);
    }

    public void addBoolean(boolean value) {
        if (encoderType != EncoderType.ARRAY) {
            throw new UnsupportedOperationException(getBadEncoderTypeMsg(encoderType, EncoderType.ARRAY));
        }
        OCRep.addBoolean(getNativeEncoder(), value);
    }

    public void addLong(long value) {
        if (encoderType != EncoderType.ARRAY) {
            throw new UnsupportedOperationException(getBadEncoderTypeMsg(encoderType, EncoderType.ARRAY));
        }
        OCRep.addLong(getNativeEncoder(), value);
    }

    public void addDouble(double value) {
        if (encoderType != EncoderType.ARRAY) {
            throw new UnsupportedOperationException(getBadEncoderTypeMsg(encoderType, EncoderType.ARRAY));
        }
        OCRep.addDouble(getNativeEncoder(), value);
    }

    public void addByteString(byte[] value) {
        if (encoderType != EncoderType.ARRAY) {
            throw new UnsupportedOperationException(getBadEncoderTypeMsg(encoderType, EncoderType.ARRAY));
        }
        OCRep.addByteString(getNativeEncoder(), value);
    }

    public void addTextString(String value) {
        if (encoderType != EncoderType.ARRAY) {
            throw new UnsupportedOperationException(getBadEncoderTypeMsg(encoderType, EncoderType.ARRAY));
        }
        OCRep.addTextString(getNativeEncoder(), value);
    }

    public void setBoolean(String key, boolean value) {
        OCRep.setBoolean(getNativeEncoder(), key, value);
    }

    public void setUnsignedInt(String key, long value) {
        OCRep.setUnsignedInt(getNativeEncoder(), key, value);
    }

    public void setLong(String key, long value) {
        OCRep.setLong(getNativeEncoder(), key, value);
    }

    public void setDouble(String key, double value) {
        OCRep.setDouble(getNativeEncoder(), key, value);
    }

    public void setByteString(String key, byte[] value) {
        OCRep.setByteString(getNativeEncoder(), key, value);
    }

    public void setTextString(String key, String value) {
        OCRep.setTextString(getNativeEncoder(), key, value);
    }

    public void setBooleanArray(String key, boolean[] value) {
        OCRep.setBooleanArray(getNativeEncoder(), key, value);
    }

    public void setLongArray(String key, long[] value) {
        OCRep.setLongArray(getNativeEncoder(), key, value);
    }

    public void setDoubleArray(String key, double[] value) {
        OCRep.setDoubleArray(getNativeEncoder(), key, value);
    }

    public void setStringArray(String key, String[] value) {
        OCRep.setStringArray(getNativeEncoder(), key, value);
    }

    CborEncoder getNativeEncoder() {
        return nativeCborEncoder;
    }

    private String getBadEncoderTypeMsg(EncoderType type, EncoderType requiredType) {
        return new String("Encoder type " + type.name() + " not allowed. Encoder type must be " + requiredType.name());
    }
}

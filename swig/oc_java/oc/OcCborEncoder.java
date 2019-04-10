package org.iotivity.oc;

import org.iotivity.*;

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

    static public OcCborEncoder createOcCborEncoder(EncoderType type) {
        if (type == null) {
            throw new IllegalArgumentException("EncoderType cannot be null");
        }

        CborEncoder nativeEncoder;

        switch (type) {
        case ROOT:
            nativeEncoder = OCMain.repBeginRootObject();
            break;
        case LINKS_ARRAY:
            nativeEncoder = OCMain.repBeginLinksArray();
            break;
        default:
            throw new IllegalArgumentException("Illegal EncoderType " + type.name());
        }

        OcCborEncoder cborEncoder = new OcCborEncoder(type, nativeEncoder);
        return cborEncoder;
    }

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
            nativeEncoder = OCMain.repBeginObject(parent.getNativeEncoder());
            break;
        case ARRAY:
            nativeEncoder = OCMain.repBeginArray(parent.getNativeEncoder());
            break;
        case ARRAY_ITEM:
            nativeEncoder = OCMain.repObjectArrayBeginItem(parent.getNativeEncoder());
            break;
        default:
            throw new IllegalArgumentException("Illegal EncoderType " + type.name());
        }

        OcCborEncoder cborEncoder = new OcCborEncoder(type, parent, false, nativeEncoder);
        return cborEncoder;
    }

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
            nativeEncoder = OCMain.repOpenObject(parent.getNativeEncoder(), key);
            break;
        case ARRAY:
            nativeEncoder = OCMain.repOpenArray(parent.getNativeEncoder(), key);
            break;
        default:
            throw new IllegalArgumentException("Illegal EncoderType " + type.name());
        }

        OcCborEncoder cborEncoder = new OcCborEncoder(type, parent, true, nativeEncoder);
        return cborEncoder;
    }

    public void done() {
        if (isDone) {
            throw new UnsupportedOperationException(
                    "done() cannot be called twice. Encoder type is " + encoderType.name());
        }

        switch (encoderType) {
        case ROOT:
            OCMain.repEndRootObject();
            break;
        case LINKS_ARRAY:
            OCMain.repEndLinksArray();
            break;
        case OBJECT:
            if (hasKey) {
                OCMain.repCloseObject(parentEncoder.getNativeEncoder(), getNativeEncoder());
            } else {
                OCMain.repEndObject(parentEncoder.getNativeEncoder(), getNativeEncoder());
            }
            break;
        case ARRAY:
            if (hasKey) {
                OCMain.repCloseArray(parentEncoder.getNativeEncoder(), getNativeEncoder());
            } else {
                OCMain.repEndArray(parentEncoder.getNativeEncoder(), getNativeEncoder());
            }
            break;
        case ARRAY_ITEM:
            OCMain.repObjectArrayEndItem(parentEncoder.getNativeEncoder(), getNativeEncoder());
            break;
        default:
            break;
        }

        isDone = true;
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
        OCMain.repAddBoolean(getNativeEncoder(), value);
    }

    public void addInt(int value) {
        if (encoderType != EncoderType.ARRAY) {
            throw new UnsupportedOperationException(getBadEncoderTypeMsg(encoderType, EncoderType.ARRAY));
        }
        OCMain.repAddInt(getNativeEncoder(), value);
    }

    public void addDouble(double value) {
        if (encoderType != EncoderType.ARRAY) {
            throw new UnsupportedOperationException(getBadEncoderTypeMsg(encoderType, EncoderType.ARRAY));
        }
        OCMain.repAddDouble(getNativeEncoder(), value);
    }

    public void addByteString(byte[] value) {
        if (encoderType != EncoderType.ARRAY) {
            throw new UnsupportedOperationException(getBadEncoderTypeMsg(encoderType, EncoderType.ARRAY));
        }
        OCMain.repAddByteString(getNativeEncoder(), value);
    }

    public void addTextString(String value) {
        if (encoderType != EncoderType.ARRAY) {
            throw new UnsupportedOperationException(getBadEncoderTypeMsg(encoderType, EncoderType.ARRAY));
        }
        OCMain.repAddTextString(getNativeEncoder(), value);
    }

    public void setBoolean(String key, boolean value) {
        OCMain.repSetBoolean(getNativeEncoder(), key, value);
    }

    public void setUnsignedInt(String key, long value) {
        OCMain.repSetUnsignedInt(getNativeEncoder(), key, value);
    }

    public void setLong(String key, long value) {
        OCMain.repSetLong(getNativeEncoder(), key, value);
    }

    public void setDouble(String key, double value) {
        OCMain.repSetDouble(getNativeEncoder(), key, value);
    }

    public void setByteString(String key, byte[] value) {
        OCMain.repSetByteString(getNativeEncoder(), key, value);
    }

    public void setTextString(String key, String value) {
        OCMain.repSetTextString(getNativeEncoder(), key, value);
    }

    public void setBooleanArray(String key, boolean[] value) {
        OCMain.repSetBooleanArray(getNativeEncoder(), key, value);
    }

    public void setLongArray(String key, long[] value) {
        OCMain.repSetLongArray(getNativeEncoder(), key, value);
    }

    public void setDoubleArray(String key, double[] value) {
        OCMain.repSetDoubleArray(getNativeEncoder(), key, value);
    }

    public void setStringArray(String key, String[] value) {
        OCMain.repSetStringArray(getNativeEncoder(), key, value);
    }

    CborEncoder getNativeEncoder() {
        return nativeCborEncoder;
    }

    private String getBadEncoderTypeMsg(EncoderType type, EncoderType requiredType) {
        return new String("Encoder type " + type.name() + " not allowed. Encoder type must be " + requiredType.name());
    }
}

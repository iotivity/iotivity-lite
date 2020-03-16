package org.iotivity;

import static org.junit.Assert.*;

import org.junit.Test;

public class OCUuidTest {

    @Test
    public void generateAndConvert() {
        // must call OCRandom.init to initialize the random number for generateUuid
        OCRandom.init();
        OCUuid testUuid = OCUuidUtil.generateUuid();
        assertNotNull(testUuid);
        String uuid_out = OCUuidUtil.uuidToString(testUuid);
        assertEquals('-', uuid_out.charAt(8));
        assertEquals('-', uuid_out.charAt(13));
        assertEquals('-', uuid_out.charAt(18));
        assertEquals('-', uuid_out.charAt(23));
        // OC_UUID_LEN is one character longer than length for the '\0' nul terminating
        // character in C
        assertEquals(OCUuidUtil.OC_UUID_LEN-1, uuid_out.length());
        // Restore random number to un-initialized state for other tests
        OCRandom.destroy();
    }
    
    @Test
    public void convertStringToUuid() {
        // Random version 4 uuid, generated using www.uuidgenerator.net
        String generated_uuid = "a4fba108-877c-469e-9270-b400839b0631";
        OCUuid testUuid = OCUuidUtil.stringToUuid(generated_uuid);
        assertEquals(generated_uuid, OCUuidUtil.uuidToString(testUuid));
    }

    @Test
    public void convertInvalidStringToUuid() {
        // Random version 4 uuid, generated using www.uuidgenerator.net with
        // invalid letters inserted to make it an invalid uuid.
        String generated_uuid = "xxxxa108-877cx469e-9270-b400839b0631";
        // stringToUuid has no error checking just verifying the function will not crash
        OCUuid testUuid = OCUuidUtil.stringToUuid(generated_uuid);
        assertNotEquals(generated_uuid, OCUuidUtil.uuidToString(testUuid));

        String long_invalid_uuid = "i-wish-i-had-a-dollar-for-every-bug-i-created-"
                + "and-fixed-then-i-would-be-a-wealthy-person";
        testUuid = OCUuidUtil.stringToUuid(long_invalid_uuid);
        assertNotEquals(long_invalid_uuid, OCUuidUtil.uuidToString(testUuid));
    }

    @Test
    public void uuidGetSetIdBytes() {
        String uuidString = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        byte[] uuidBytes = {0x6b, (byte)0xa7, (byte)0xb8, 0x10,
                (byte)0x9d, (byte)0xad, 0x11, (byte)0xd1,
                (byte)0x80, (byte)0xb4, 0x00, (byte)0xc0,
                0x4f, (byte)0xd4, (byte)0x30, (byte)0xc8 };
        OCUuid uuid1 = OCUuidUtil.stringToUuid(uuidString);

        assertEquals(16, uuid1.getId().length);
        assertArrayEquals(uuidBytes, uuid1.getId());
        
        OCUuid uuid2 = new OCUuid();
        uuid2.setId(uuidBytes);
        assertEquals(uuidString, OCUuidUtil.uuidToString(uuid2));
    }

}

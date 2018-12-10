package org.iotivity;

import static org.junit.Assert.*;

import org.junit.Test;

public class OCUuidTest {

    @Test
    public void generate_and_convert() {
        OCUuidType testUuid = OCUuid.generateUuid();
        assertNotNull(testUuid);
        System.out.println(OCUuid.uuidToString(testUuid));
    }

}

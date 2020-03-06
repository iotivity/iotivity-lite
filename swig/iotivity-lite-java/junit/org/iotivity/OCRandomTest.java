package org.iotivity;

import static org.junit.Assert.*;
import org.junit.Test;

public class OCRandomTest {
    @Test
    public void randomValue() {
        OCRandom.init();
        assertNotEquals(OCRandom.randomValue(), OCRandom.randomValue());
        OCRandom.destroy();
    }
}

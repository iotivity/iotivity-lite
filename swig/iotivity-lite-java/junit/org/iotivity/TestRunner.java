package org.iotivity;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.internal.TextListener;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;

public class TestRunner {
    public static void main(String args[]) {
        JUnitCore junit = new JUnitCore();
        junit.addListener(new TextListener(System.out));
        Result result = junit.run(
                OCMainTest.class,
                OCRepresentationTest.class,
                OCResourceTest.class,
                OCUuidTest.class);
        if (result.getFailureCount() > 0) {
          System.out.println("Test failed.");
          System.exit(1);
        } else {
          System.out.println("Test finished successfully.");
          System.exit(0);
        }
      }
}

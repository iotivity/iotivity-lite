package org.iotivity;

public class OCQueryValue {
  public final String key;
  public final String value;

  public OCQueryValue(String key, String value) {
    this.key = key;
    this.value = value;
  }

  public String getKey() {
    return key;
  }

  public String getValue() {
    return value;
  }
}
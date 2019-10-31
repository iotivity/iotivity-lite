package org.iotivity.multideviceserver;

public class Refrigerator {

    static public final String FILTER_KEY = "filter";
    static public final String RAPID_FREEZE_KEY = "rapidFreeze";
    static public final String RAPID_COOL_KEY = "rapidCool";
    static public final String DEFROST_KEY = "defrost";

    private String name;
    private int filter;
    private boolean rapidFreeze;
    private boolean rapidCool;
    private boolean defrost;

    public Refrigerator(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public int getFilter() {
        return filter;
    }

    public void setFilter(int filter) {
        this.filter = filter;
    }

    public boolean isRapidFreeze() {
        return rapidFreeze;
    }

    public void setRapidFreeze(boolean rapidFreeze) {
        this.rapidFreeze = rapidFreeze;
    }

    public boolean isRapidCool() {
        return rapidCool;
    }

    public void setRapidCool(boolean rapidCool) {
        this.rapidCool = rapidCool;
    }

    public boolean isDefrost() {
        return defrost;
    }

    public void setDefrost(boolean defrost) {
        this.defrost = defrost;
    }
}

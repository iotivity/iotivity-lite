package java_oc_simple_server;

public class Counter {

    private String name;
    private long counter;

    public Counter(String name) {
        this(name, 0);
    }

    public Counter(String name, int counter) {
        setName(name);
        setCounter(counter);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public long getCounter() {
        return counter;
    }

    public void setCounter(long counter) {
        this.counter = counter;
    }
}

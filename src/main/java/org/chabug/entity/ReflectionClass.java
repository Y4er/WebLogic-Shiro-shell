package org.chabug.entity;

import java.io.IOException;

public class ReflectionClass {
    String name;

    public ReflectionClass(String name) {
        this.name = name;
    }

    public ReflectionClass() {
    }

    public String say() {
        return this.name;
    }

    private void evil(String cmd) {
        try {
            Runtime.getRuntime().exec(new String[]{"cmd","/c",cmd});
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String toString() {
        return "ReflectionClass{" +
                "name='" + name + '\'' +
                '}';
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}

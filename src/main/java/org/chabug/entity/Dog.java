package org.chabug.entity;

import java.io.ObjectInputStream;
import java.io.Serializable;

public class Dog implements Serializable {
    String name;

    @Override
    public String toString() {
        return getName();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    private void readObject(ObjectInputStream in) throws Exception {
        //执行默认的readObject()方法
        in.defaultReadObject();
    }
}

package org.chabug.entity;

import java.io.ObjectInputStream;
import java.io.Serializable;

public class EvilClass implements Serializable {
    String name;

    public EvilClass() {
        System.out.println(this.getClass() + "的EvilClass()构造方法被调用!!!!!!");
    }

    public EvilClass(String name) {
        System.out.println(this.getClass() + "的EvilClass(String name)构造方法被调用!!!!!!");
        this.name = name;
    }

    public String getName() {
        System.out.println(this.getClass() + "的getName被调用!!!!!!");
        return name;
    }

    public void setName(String name) {
        System.out.println(this.getClass() + "的setName被调用!!!!!!");
        this.name = name;
    }

    @Override
    public String toString() {
        System.out.println(this.getClass() + "的toString()被调用!!!!!!");
        return "EvilClass{" +
                "name='" + getName() + '\'' +
                '}';
    }

    private void readObject(ObjectInputStream in) throws Exception {
        //执行默认的readObject()方法
        in.defaultReadObject();
        System.out.println(this.getClass() + "readObject()被调用!!!!!!");
        Runtime.getRuntime().exec(new String[]{"cmd", "/c", name});
    }
}

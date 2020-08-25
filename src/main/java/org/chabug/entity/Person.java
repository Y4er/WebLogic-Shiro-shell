package org.chabug.entity;

import java.io.ObjectInputStream;
import java.io.Serializable;

public class Person implements Serializable {
    String name;
    String sex;
    int age;
    Dog dog;

    public Person() {
    }

    public Person(String name, String sex, int age, Dog dog) {
        this.name = name;
        this.sex = sex;
        this.age = age;
        this.dog = dog;
    }

    @Override
    public String toString() {
        return "Person{" +
                "name='" + name + '\'' +
                ", sex='" + sex + '\'' +
                ", age=" + age +
                ", dog=" + dog +
                '}';
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSex() {
        return sex;
    }

    public void setSex(String sex) {
        this.sex = sex;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public Dog getDog() {
        return dog;
    }

    public void setDog(Dog dog) {
        this.dog = dog;
    }

    private void readObject(ObjectInputStream in) throws Exception {
        //执行默认的readObject()方法
        in.defaultReadObject();
    }
}

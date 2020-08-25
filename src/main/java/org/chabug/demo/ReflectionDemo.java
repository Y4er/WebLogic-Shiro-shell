package org.chabug.demo;

import org.chabug.entity.ReflectionClass;

import java.lang.reflect.Method;

public class ReflectionDemo {
    public static void main(String[] args) throws Exception {
        ReflectionClass demo = new ReflectionClass();
        demo.setName("hello");
        System.out.println(demo.say());
//        demo.evil("calc");    // 不能够调用private方法

        // new
        Class<?> aClass = Class.forName("org.chabug.entity.ReflectionClass");
        Object o = aClass.newInstance();

        // setName("jack")
        Method setName = aClass.getDeclaredMethod("setName",String.class);
        setName.invoke(o, "jack");

        // say()
        Method say = aClass.getDeclaredMethod("say",null);
        Object o1 = say.invoke(o, null);
        System.out.println(o1);

        // evil("calc")
        // 反射可以修改方法的修饰符来调用private方法
        Method evil = aClass.getDeclaredMethod("evil", String.class);
        evil.setAccessible(true);
        evil.invoke(o,"calc");


    }
}

package org.chabug.demo;

import org.chabug.entity.Dog;
import org.chabug.entity.Person;
import org.chabug.util.Serializables;

/*
这个例子是为了证明只要实现了Serializable接口的类都可以被序列化
并且Java内置的几大数据类型也可被序列化，因为他们都继承了Object类
 */

public class SerializeAndDeserialize {

    public static void main(String[] args) throws Exception {
        byte[] bytes;
        String s1 = "I'm a String Object....";
        bytes = Serializables.serializeToBytes(s1);
        Object o1 = Serializables.deserializeFromBytes(bytes);
        System.out.println(o1);

        String[] s2 = new String[]{"tom", "bob", "jack"};
        bytes = Serializables.serializeToBytes(s2);
        String[] o2 = (String[])Serializables.deserializeFromBytes(bytes);
        System.out.println(o2);

        int i = 123;
        bytes = Serializables.serializeToBytes(i);
        int o3 = (Integer) Serializables.deserializeFromBytes(bytes);
        System.out.println(o3);

        // 一只名叫woody的狗
        Dog dog = new Dog();
        dog.setName("woody");

        // tom
        Person tom = new Person();
        tom.setAge(14);
        tom.setName("tom");
        tom.setSex("男");
        tom.setDog(dog);

        bytes = Serializables.serializeToBytes(tom);
        Person o = (Person) Serializables.deserializeFromBytes(bytes);
        System.out.println(o);

    }
}

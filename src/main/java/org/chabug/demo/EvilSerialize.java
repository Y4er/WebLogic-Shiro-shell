package org.chabug.demo;

import org.chabug.entity.EvilClass;
import org.chabug.util.Serializables;

public class EvilSerialize {
    public static void main(String[] args) throws Exception {
        EvilClass evilObj = new EvilClass();
        evilObj.setName("calc");
        byte[] bytes = Serializables.serializeToBytes(evilObj);
        EvilClass o = (EvilClass) Serializables.deserializeFromBytes(bytes);
        System.out.println(o);
    }
}

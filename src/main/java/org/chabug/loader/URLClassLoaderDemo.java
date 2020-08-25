package org.chabug.loader;

import java.net.URL;
import java.net.URLClassLoader;

public class URLClassLoaderDemo {
    public static void main(String[] args) throws Exception {
//        URL url = new URL("https://baidu.com/cmd.jar");   // 也可以加载远程jar
        URL url = new URL("file:///E:/code/java/JavaSerialize/calc.jar");

        // 创建URLClassLoader对象，并加载远程jar包
        URLClassLoader ucl = new URLClassLoader(new URL[]{url});

        // 通过URLClassLoader加载jar包
        Class<?> aClass = ucl.loadClass("org.chabug.demo.Calc");
        aClass.newInstance();
    }
}

package org.chabug.loader;

import static org.chabug.loader.BytecodeLoaderLoader.getBytesByFile;

public class MyLoader extends ClassLoader {
    public static String className = "org.chabug.demo.Calc";
    public static byte[] bytes = getBytesByFile("E:\\code\\java\\JavaSerialize\\target\\classes\\org\\chabug\\demo\\Calc.class");

    public static void main(String[] args) throws Exception {
        new MyLoader().loadClass(className).newInstance();
    }

    @Override
    public Class<?> findClass(String name) throws ClassNotFoundException {
        // 只处理TestHelloWorld类
        if (name.equals(className)) {
            // 调用JVM的native方法定义TestHelloWorld类
            return defineClass(className, bytes, 0, bytes.length);
        }

        return super.findClass(name);
    }
}

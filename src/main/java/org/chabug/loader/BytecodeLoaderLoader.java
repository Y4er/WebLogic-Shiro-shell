package org.chabug.loader;

import org.python.util.PythonInterpreter;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;

public class BytecodeLoaderLoader {
    public static void main(String[] args) throws Exception {
        String className = "org.chabug.demo.Calc";
        byte[] bytes = getBytesByFile("E:\\code\\java\\JavaSerialize\\target\\classes\\org\\chabug\\demo\\Calc.class");
        String classBytes = "";
        for (byte b : bytes) {
            classBytes += String.format("%s%s", b, ",");
        }
        String s = String.format("from org.python.core import BytecodeLoader;\n" +
                "from jarray import array\n" +
                "myList = [%s]\n" +
                "bb = array( myList, 'b')\n" +
                "BytecodeLoader.makeClass(\"%s\",None,bb).getConstructor([]).newInstance([]);", classBytes, className);
        PythonInterpreter instance = PythonInterpreter.class.getConstructor(null).newInstance();
        instance.exec(s);

    }

    public static byte[] getBytesByFile(String pathStr) {
        File file = new File(pathStr);
        try {
            FileInputStream fis = new FileInputStream(file);
            ByteArrayOutputStream bos = new ByteArrayOutputStream(1000);
            byte[] b = new byte[1000];
            int n;
            while ((n = fis.read(b)) != -1) {
                bos.write(b, 0, n);
            }
            fis.close();
            byte[] data = bos.toByteArray();
            bos.close();
            return data;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}

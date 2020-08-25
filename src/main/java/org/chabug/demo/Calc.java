package org.chabug.demo;

import java.io.IOException;

public class Calc {
    static {
        try {
            Runtime.getRuntime().exec(new String[]{"cmd", "/c", "calc"});
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

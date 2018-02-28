package org.aerogear.mobile.aspects;


public class AAA {
    @DebugTrace
    private void testAnnotatedMethod() {
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new AAA().testAnnotatedMethod();
    }
}

package com.smx;

import org.osgi.framework.BundleContext;

public class SmxBundleActivator implements org.osgi.framework.BundleActivator {
    private static BundleContext thisContext;

    public static BundleContext getBundleContext(){
        return thisContext;
    }

    @Override
    public void start(BundleContext context) throws Exception {
        thisContext = context;
    }

    @Override
    public void stop(BundleContext context) throws Exception {
    }
}

package org.jnetpcap.license;

import org.jnetpcap.Pcap;

import com.cryptlex.lexactivator.LexActivator;

public class MainTest {
    public static void main(String[] args) throws Exception {
        String version = Pcap.VERSION;
        String key = null;

        for (int i = 0; i < args.length; i++) {
            if ("--license".equals(args[i]) && i + 1 < args.length) key = args[i + 1];
            if ("--version".equals(args[i]) && i + 1 < args.length) version = args[i + 1];
        }

        if (key != null) LexActivator.SetLicenseKey(key);

        System.out.println("jnetpcap License Test – Version: " + version);
        System.out.println("------------------------------------------------");
        LicenseInit.init(version);
    }
}
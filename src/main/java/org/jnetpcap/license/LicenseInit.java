// src/main/java/org/jnetpcap/license/LicenseInit.java
package org.jnetpcap.license;

import java.io.UnsupportedEncodingException;

import com.cryptlex.lexactivator.FeatureEntitlement;
import com.cryptlex.lexactivator.LexActivator;
import com.cryptlex.lexactivator.LexActivatorException;

public final class LicenseInit {

    private static final String PRODUCT_ID   = "019a99d8-73fc-7921-ad68-d1b446253220";
    private static final String FIVE_ACTIVATIONS = "D4DC4D-D408E4-4F48BD-64AB5F-BE5100-6FFCCD";
    private static final String PRODUCT_DATA = "MzRCOTU4RjdBNEMzOUE4MTAyODY0QTYyMDI3MjAzQTM=.GX6/K+PTVYi/IAAfiUQbMibbEt0byq2RXGOjl43FPrY6ccjRzW/Zn8s0tPYu99EMA/NW98U0qlzKdNCDOmYcUNQW46gRKecUjiE0/K10llgAxWluDzNlOoeDP8zz/c/HiFoOdAQUysfKJBb79Fs/QZec4DpFUqZoutwb2fnuO+6YxMtEPoQqyRNrFEE2T4JmK1xiXTwhPL9U38Q7bP/EtMn/IDoumcLTfdMxfW2jOjZDPWNBYi/SYeu1kaJdYBNA/sZ7IVDvha6fIOz7vs4tdNxilnX02T458RU8d482BYtrYrWh6sp0m1Y8wYn5ieZvIZ+ME/F3aCgh9Ff5CRj3oj8Y+e7ysagtK5KebT0yGkQg6iHSwbl/GQpebkAGGsWySU3RXqIrdOeGbuvWbb2EooG0hB43HISRfdm3KyTbj/3Ia/St7TSxV8DEbQGzN62vsVjZ6Ka54iDMXFfy4SPTeZ5khZDIa88Bj0TcPNsTv7ddMeaikPvF+shIba+PAb4U7OlYRWqhOvBTJvVj3jkc1Ae1exCQVH3z+fcJwDi27hOAfIFJXg6X/HKXkDZx4FSNvd3y9AiU92s3WThmFJv2IYumMGrK+ZvLi7XzAaH4KglQeEu1YgZk1Ddj5UB6pZlu0QsyzW69u6b97xMrm42aIsBezmmM8ONDr79Svn3/QxHV5myDGzR11OTsrJQKUwMtddJVNdXuXKQUKaMUx6Lzg5n88OOoD7eiy7YEa7MFs0rjYrKid/G1OFYgo+9VSRPjOf6OSzky9hy2ZXeF1tD3V36DQ1Dv8caGNOS2fYt2LjWcbuG7xTusOjb55qjlkOus";
    private static final String COMMUNITY_KEY = "4EA214-2858D5-41D389-DED990-F96F95-94BCF4";

    private static boolean initialized = false;

    private LicenseInit() {}

    public static synchronized void init(String appVersion) throws LexActivatorException, UnsupportedEncodingException {
        if (initialized) return;
        initialized = true;

        LexActivator.SetProductData(PRODUCT_DATA);
        LexActivator.SetProductId(PRODUCT_ID, LexActivator.LA_USER);
        LexActivator.SetLicenseKey(FIVE_ACTIVATIONS);
        LexActivator.SetReleaseVersion(appVersion);

        // Silent first-time activation for telemetry
        int status = LexActivator.ActivateLicense();
        if (status != LexActivator.LA_OK && status != LexActivator.LA_EXPIRED && status != LexActivator.LA_SUSPENDED) {
            LexActivator.IsLicenseGenuine(); // fallback if offline
        }

        status = LexActivator.IsLicenseGenuine();
        if (status != LexActivator.LA_OK) {
            System.out.println("jnetpcap Community Edition – running offline/community mode");
            return;
        }

        // === SAFE: feature may not exist on community key ===
        boolean isCommercial = isFeatureYes("commercial-use");
        if (isCommercial) {
            boolean isUnlimited = isFeatureYes("unlimited-activations");
            if (isUnlimited) {
                System.out.println("jnetpcap Commercial Edition – Unlimited activations");
            } else {
                long allowed = LexActivator.GetLicenseAllowedActivations();
                System.out.println("jnetpcap Commercial Edition – " + allowed + " seats");
            }
        } else {
            System.out.println("jnetpcap Community Edition (Apache 2.0 + telemetry)");
        }
    }

    // Helper that returns false instead of throwing when feature doesn't exist
    private static boolean isFeatureYes(String featureName) throws UnsupportedEncodingException {
        try {
            FeatureEntitlement ent = LexActivator.GetFeatureEntitlement(featureName);
            return ent != null && "yes".equals(ent.value);
        } catch (LexActivatorException e) {
            // Code 47 = LA_E_FEATURE_NOT_FOUND → normal for community key
            return false;
        }
    }
}
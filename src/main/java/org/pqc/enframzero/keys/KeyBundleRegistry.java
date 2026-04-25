package org.pqc.enframzero.keys;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe registry of named {@link PqcKeyBundle} instances.
 *
 * <p>One bundle is designated as the <em>master</em> (id = {@value #MASTER}) and is always
 * present. Additional bundles can be registered explicitly via {@link #register}, or created
 * on demand via {@link #getOrCreate} using the supplied {@link PqcKeyManager}.
 *
 * <p>Auto-created bundles are held in memory only. Callers are responsible for persisting
 * them via {@link KmsBlobKeyStore} if they need to survive process restarts.
 */
public final class KeyBundleRegistry {

    public static final String MASTER = "master";

    private final ConcurrentHashMap<String, PqcKeyBundle> bundles = new ConcurrentHashMap<>();
    private final PqcKeyManager keyManager;

    public KeyBundleRegistry(PqcKeyBundle masterBundle, PqcKeyManager keyManager) {
        this.keyManager = keyManager;
        bundles.put(MASTER, masterBundle);
    }

    /** Registers an existing bundle under the given id, replacing any prior entry. */
    public void register(String bundleId, PqcKeyBundle bundle) {
        bundles.put(bundleId, bundle);
    }

    /**
     * Returns the bundle for {@code bundleId}, auto-creating and registering it
     * (via {@link PqcKeyManager#generateKeys()}) if not yet present.
     */
    public PqcKeyBundle getOrCreate(String bundleId) {
        return bundles.computeIfAbsent(bundleId, id -> keyManager.generateKeys());
    }

    /**
     * Returns the bundle for {@code bundleId}, or empty if it has not been registered.
     * Unlike {@link #getOrCreate}, this never auto-creates.
     */
    public Optional<PqcKeyBundle> get(String bundleId) {
        return Optional.ofNullable(bundles.get(bundleId));
    }

    /** Convenience: returns the master bundle (always present). */
    public PqcKeyBundle master() {
        return bundles.get(MASTER);
    }
}

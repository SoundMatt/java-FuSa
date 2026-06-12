package com.soundmatt.jfusa.runtime;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Runnable;
import java.util.logging.Logger;

/**
 * Reusable runtime safety pattern: safe-state guard.
 *
 * <p>Manages the transition to a defined safe state. Once entered, subsequent
 * entry attempts are no-ops (idempotent). All safe-state entry points must
 * be annotated {@code //fusa:safe-state} per spec §2.5.
 *
 * <pre>{@code
 * SafeStateGuard guard = new SafeStateGuard("ACTUATOR_SYSTEM");
 * guard.onEnter(() -> actuator.deEnergise());
 * guard.onEnter(() -> log.audit("safe state entered"));
 *
 * // In a fault handler:
 * //fusa:safe-state fault detected in sensor pipeline
 * guard.enter("sensor fault");
 * }</pre>
 */
//fusa:req REQ-RT003
public final class SafeStateGuard {

    private static final Logger LOG = Logger.getLogger(SafeStateGuard.class.getName());

    private final String systemId;
    private final AtomicBoolean inSafeState = new AtomicBoolean(false);
    private final List<Runnable> onEnterHandlers = new ArrayList<>();
    private volatile String reason;
    private volatile Instant enteredAt;

    public SafeStateGuard(String systemId) {
        this.systemId = systemId;
    }

    /** Register an action to run when safe state is entered. */
    public synchronized SafeStateGuard onEnter(Runnable action) {
        onEnterHandlers.add(action);
        return this;
    }

    /**
     * Transition to safe state. Idempotent — subsequent calls are no-ops.
     * Must be called from a site annotated {@code //fusa:safe-state}.
     */
    //fusa:safe-state this is the canonical entry point
    public void enter(String reason) {
        if (inSafeState.compareAndSet(false, true)) {
            this.reason = reason;
            this.enteredAt = Instant.now();
            LOG.warning("[" + systemId + "] entering safe state: " + reason);
            for (Runnable h : onEnterHandlers) {
                try { h.run(); }
                catch (Exception e) { LOG.severe("safe-state handler failed: " + e.getMessage()); }
            }
        }
    }

    public boolean isInSafeState() { return inSafeState.get(); }
    public String reason()         { return reason; }
    public Instant enteredAt()     { return enteredAt; }
    public String systemId()       { return systemId; }
}
